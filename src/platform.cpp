#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <optional>
#include <set>

#include "fixer.hpp"
#ifdef _WIN32
// Windows API headers require this include order.
// clang-format off
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <wincrypt.h>
// clang-format on
#else
#include <fcntl.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace fixer {
namespace {
#ifdef _WIN32
struct Handle {
  HANDLE value = INVALID_HANDLE_VALUE;

  explicit Handle(HANDLE h) : value(h) {}

  ~Handle() {
    if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
  }
};

void regular_handle(HANDLE h) {
  BY_HANDLE_FILE_INFORMATION info{};
  require(GetFileInformationByHandle(h, &info) != 0,
          "Cannot inspect file handle", Code::failure);
  require(!(info.dwFileAttributes &
            (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
          "Not a regular file");
  require(GetFileType(h) == FILE_TYPE_DISK, "Not a disk file");
  require(info.nNumberOfLinks == 1, "Hard-linked file rejected");
}

Bytes token_user() {
  HANDLE raw = nullptr;
  require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != 0,
          "Cannot read user token", Code::failure);
  Handle token(raw);
  DWORD size = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
  Bytes buffer(size);
  require(GetTokenInformation(token.value, TokenUser, buffer.data(), size,
                              &size) != 0,
          "Cannot read user SID", Code::failure);
  return buffer;
}

void check_private_acl(const fs::path &path) {
  auto token = token_user();
  auto user = reinterpret_cast<TOKEN_USER *>(token.data())->User.Sid;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  require(GetNamedSecurityInfoW(
              const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT,
              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
              nullptr, &dacl, nullptr, &descriptor) == ERROR_SUCCESS,
          "Cannot inspect managed directory ACL", Code::failure);
  struct Free {
    PSECURITY_DESCRIPTOR value;
    ~Free() { LocalFree(value); }
  } free{descriptor};
  require(owner && EqualSid(owner, user) && dacl,
          "Managed directory is not privately owned");
  BYTE system[SECURITY_MAX_SID_SIZE]{};
  DWORD length = sizeof(system);
  require(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &length) != 0,
          "Cannot inspect SYSTEM SID", Code::failure);
  for (DWORD i = 0; i < dacl->AceCount; ++i) {
    void *pointer = nullptr;
    require(GetAce(dacl, i, &pointer) != 0, "Cannot inspect ACL entry",
            Code::failure);
    const auto header = static_cast<ACE_HEADER *>(pointer);
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    require(header->AceType == ACCESS_ALLOWED_ACE_TYPE,
            "Unsupported managed ACL entry");
    auto ace = static_cast<ACCESS_ALLOWED_ACE *>(pointer);
    auto sid = reinterpret_cast<PSID>(&ace->SidStart);
    require(EqualSid(sid, user) || EqualSid(sid, system),
            "Managed directory permits other users");
  }
}

fs::path env_path(const wchar_t *name) {
  DWORD count = GetEnvironmentVariableW(name, nullptr, 0);
  if (!count) return {};
  std::wstring text(count, L'\0');
  const auto length = GetEnvironmentVariableW(name, text.data(), count);
  require(length && length < count, "Cannot read environment", Code::failure);
  text.resize(length);
  return fs::path(text);
}
fs::path local_app_data() {
  auto local = env_path(L"LOCALAPPDATA");
  if (local.empty()) {
    const auto profile = env_path(L"USERPROFILE");
    if (!profile.empty()) {
      require(profile.is_absolute(), "USERPROFILE must be absolute");
      local = profile / "AppData" / "Local";
    }
  }
  require(local.empty() || local.is_absolute(),
          "LOCALAPPDATA must be absolute");
  return local;
}
#else
struct Handle {
  int value = -1;

  explicit Handle(int fd) : value(fd) {}

  ~Handle() {
    if (value >= 0) close(value);
  }
};
void regular_handle(int fd) {
  struct stat info{};
  require(fstat(fd, &info) == 0, "Cannot inspect file handle", Code::failure);
  require(S_ISREG(info.st_mode), "Not a regular file");
  require(info.st_nlink == 1, "Hard-linked file rejected");
}
fs::path env_path(const char *name) {
  auto value = std::getenv(name);
  return value && *value ? fs::path(value) : fs::path{};
}
#endif
using DirectoryHandles = std::vector<std::unique_ptr<Handle>>;

// Open each component without following links. Retain the handles until the
// operation finishes: Windows denies ancestor renames; Linux operates relative
// to the original directory descriptors even if an ancestor is renamed.
DirectoryHandles pin_directory(const fs::path &path) {
  const auto absolute = fs::absolute(path);
  DirectoryHandles handles;
  auto open_component = [&](const fs::path &component, const fs::path &full) {
#ifdef _WIN32
    auto handle = std::make_unique<Handle>(CreateFileW(
        full.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(handle->value != INVALID_HANDLE_VALUE,
            "Cannot pin directory: " + utf8(full), Code::failure);
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(handle->value, &info) != 0,
            "Cannot inspect directory handle", Code::failure);
    require((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "Directory handle points to a reparse point or non-directory");
    (void)component;
#else
    const auto flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
    auto handle = std::make_unique<Handle>(
        handles.empty()
            ? open(full.c_str(), flags)
            : openat(handles.back()->value, component.c_str(), flags));
    require(handle->value >= 0, "Cannot pin directory: " + utf8(full),
            Code::failure);
#endif
    handles.push_back(std::move(handle));
  };
  auto current = absolute.root_path();
  open_component(current, current);
  for (const auto &component : absolute.relative_path()) {
    require(component != "." && component != "..", "Unnormalized directory");
    current /= component;
    open_component(component, current);
  }
  return handles;
}
std::optional<fs::path> latest_version_dir(const fs::path &root) {
  if (!fs::is_directory(root)) return std::nullopt;
  assert_safe_path(root, false);
  std::optional<fs::path> best;
  std::array<std::uint32_t, 4> best_version{};
  std::set<std::array<std::uint32_t, 4>> versions;
  for (const auto &entry : fs::directory_iterator(root)) {
    if (!entry.is_directory()) continue;
    std::array<std::uint32_t, 4> version{};
    try {
      version = version_parts(utf8(entry.path().filename()));
    } catch (const Error &) {
      continue;
    }
    require(versions.insert(version).second, "Ambiguous version directories");
    if (!best || version > best_version) {
      best = entry.path();
      best_version = version;
    }
  }
  return best;
}
}  // namespace
std::string platform_name() {
#ifdef _WIN32
  return "win";
#else
  return "linux";
#endif
}

std::string binary_name() {
#ifdef _WIN32
  return "widevinecdm.dll";
#else
  return "libwidevinecdm.so";
#endif
}

void assert_safe_path(const fs::path &path, bool allow_missing) {
  require(!path.empty(), "Empty path");
  const auto full = fs::absolute(path);
#ifdef _WIN32
  require(full.native().size() <= 240 &&
              full.native().starts_with(full.root_name().native()) &&
              full.root_name().native().size() == 2,
          "Unsupported UNC, device or overlong path");
#endif
  fs::path partial;
  for (const auto &component : full) {
    require(component != ".." && component != ".", "Unnormalized path");
    partial /= component;
#ifdef _WIN32
    const auto attrs = GetFileAttributesW(partial.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
      const auto e = GetLastError();
      require(allow_missing &&
                  (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND),
              "Cannot inspect path: " + utf8(partial), Code::failure);
      continue;
    }
    require(!(attrs & FILE_ATTRIBUTE_REPARSE_POINT),
            "Reparse point rejected: " + utf8(partial));
#else
    struct stat info{};
    if (lstat(partial.c_str(), &info) != 0) {
      require(allow_missing && errno == ENOENT,
              "Cannot inspect path: " + utf8(partial), Code::failure);
      continue;
    }
    require(!S_ISLNK(info.st_mode), "Symlink rejected: " + utf8(partial));
#endif
  }
}

Bytes read_file(const fs::path &path, std::size_t limit, bool prefix_only) {
  assert_safe_path(path, false);
  const auto parent = pin_directory(fs::absolute(path).parent_path());
#ifdef _WIN32
  Handle file(CreateFileW(
      path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  require(file.value != INVALID_HANDLE_VALUE, "Cannot read: " + utf8(path),
          Code::failure);
  regular_handle(file.value);
  LARGE_INTEGER size{};
  require(
      GetFileSizeEx(file.value, &size) && size.QuadPart >= 0 &&
          (prefix_only || static_cast<std::uint64_t>(size.QuadPart) <= limit),
      "File exceeds size limit");
  Bytes out(static_cast<std::size_t>(std::min<std::uint64_t>(
      static_cast<std::uint64_t>(size.QuadPart), limit)));
  std::size_t pos = 0;
  while (pos < out.size()) {
    DWORD count = 0;
    require(ReadFile(file.value, out.data() + pos,
                     static_cast<DWORD>(
                         std::min<std::size_t>(65536, out.size() - pos)),
                     &count, nullptr) &&
                count > 0,
            "File read failed", Code::failure);
    pos += count;
  }
#else
  Handle file(openat(parent.back()->value, path.filename().c_str(),
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
  require(file.value >= 0, "Cannot read: " + utf8(path), Code::failure);
  regular_handle(file.value);
  struct stat info{};
  require(
      fstat(file.value, &info) == 0 && info.st_size >= 0 &&
          (prefix_only || static_cast<std::uint64_t>(info.st_size) <= limit),
      "File exceeds size limit");
  Bytes out(static_cast<std::size_t>(std::min<std::uint64_t>(
      static_cast<std::uint64_t>(info.st_size), limit)));
  std::size_t pos = 0;
  while (pos < out.size()) {
    const auto count = read(file.value, out.data() + pos,
                            std::min<std::size_t>(65536, out.size() - pos));
    if (count < 0 && errno == EINTR) continue;
    require(count > 0, "File read failed", Code::failure);
    pos += static_cast<std::size_t>(count);
  }
#endif
  return out;
}

namespace {
void write_in_directory(const fs::path &path,
                        std::span<const unsigned char> data,
                        const DirectoryHandles &parent, bool &created) {
#ifdef _WIN32
  (void)parent;
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                          nullptr));
  require(file.value != INVALID_HANDLE_VALUE,
          "Cannot exclusively create: " + utf8(path), Code::failure);
  created = true;
  std::size_t pos = 0;
  while (pos < data.size()) {
    DWORD count = 0;
    require(WriteFile(file.value, data.data() + pos,
                      static_cast<DWORD>(
                          std::min<std::size_t>(65536, data.size() - pos)),
                      &count, nullptr) &&
                count > 0,
            "Write failed", Code::failure);
    pos += count;
  }
  require(FlushFileBuffers(file.value) != 0, "Cannot flush file",
          Code::failure);
#else
  Handle file(openat(parent.back()->value, path.filename().c_str(),
                     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     0600));
  require(file.value >= 0, "Cannot exclusively create: " + utf8(path),
          Code::failure);
  created = true;
  std::size_t pos = 0;
  while (pos < data.size()) {
    const auto count = write(file.value, data.data() + pos, data.size() - pos);
    if (count < 0 && errno == EINTR) continue;
    require(count > 0, "Write failed", Code::failure);
    pos += static_cast<std::size_t>(count);
  }
  require(fsync(file.value) == 0, "Cannot flush file", Code::failure);
#endif
}
}  // namespace

void write_file(const fs::path &path, std::span<const unsigned char> data) {
  assert_safe_path(path);
  const auto parent = pin_directory(fs::absolute(path).parent_path());
  bool created = false;
  write_in_directory(path, data, parent, created);
}

void write_text(const fs::path &path, const std::string &text) {
  write_file(path, {reinterpret_cast<const unsigned char *>(text.data()),
                    text.size()});
}

void sync_dir(const fs::path &path) {
#ifndef _WIN32
  const auto directory = pin_directory(path);
  require(fsync(directory.back()->value) == 0, "Cannot sync directory",
          Code::failure);
#else
  (void)path;  // MoveFileExW uses WRITE_THROUGH; Windows has no general
               // directory fsync API.
#endif
}

void durable_rename(const fs::path &source, const fs::path &dest,
                    const std::function<void()> &before_rename) {
  assert_safe_path(source, false);
  assert_safe_path(dest);
  require(!fs::exists(dest), "Rename destination already exists");
  const auto source_parent = pin_directory(fs::absolute(source).parent_path());
  const auto dest_parent = pin_directory(fs::absolute(dest).parent_path());
  if (before_rename) before_rename();
#ifdef _WIN32
  require(
      MoveFileExW(source.c_str(), dest.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
      "Cannot rename: " + utf8(source), Code::failure);
#else
  // A preceding existence check alone cannot prevent a concurrently created
  // destination from being overwritten by plain rename(). Never fall back to
  // it.
  require(
      syscall(SYS_renameat2, source_parent.back()->value,
              source.filename().c_str(), dest_parent.back()->value,
              dest.filename().c_str(), RENAME_NOREPLACE) == 0,
      "Cannot rename without replacement (renameat2 required): " + utf8(source),
      Code::failure);
  require(fsync(source_parent.back()->value) == 0 &&
              fsync(dest_parent.back()->value) == 0,
          "Cannot sync renamed directories", Code::failure);
#endif
}

void replace_text(const fs::path &path, const std::string &text) {
  assert_safe_path(path);
  const auto parent = pin_directory(fs::absolute(path).parent_path());
  const auto temporary =
      path.parent_path() / (utf8(path.filename()) + ".tmp-" + random_id());
  bool created = false;
  try {
    write_in_directory(
        temporary,
        {reinterpret_cast<const unsigned char *>(text.data()), text.size()},
        parent, created);
#ifdef _WIN32
    require(
        MoveFileExW(temporary.c_str(), path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0,
        "Cannot replace journal", Code::failure);
#else
    require(renameat(parent.back()->value, temporary.filename().c_str(),
                     parent.back()->value, path.filename().c_str()) == 0,
            "Cannot replace journal", Code::failure);
    require(fsync(parent.back()->value) == 0, "Cannot sync journal directory",
            Code::failure);
#endif
  } catch (...) {
    if (created) {
#ifdef _WIN32
      std::error_code ignored;
      fs::remove(temporary, ignored);
#else
      (void)unlinkat(parent.back()->value, temporary.filename().c_str(), 0);
#endif
    }
    throw;
  }
}

void assert_private_dir(const fs::path &path) {
  assert_safe_path(path, false);
  require(fs::is_directory(path), "Expected a directory");
  const auto existing = pin_directory(path);
#ifdef _WIN32
  check_private_acl(path);
#else
  struct stat info{};
  require(fstat(existing.back()->value, &info) == 0 &&
              info.st_uid == geteuid() && (info.st_mode & 0077) == 0,
          "Managed directory is not private or not owned by this user");
#endif
}

void create_private_dir(const fs::path &path, bool exclusive) {
  assert_safe_path(path);
  const auto parent = pin_directory(fs::absolute(path).parent_path());
  if (fs::exists(path)) {
    require(!exclusive, "Private directory already exists", Code::failure);
    assert_private_dir(path);
    return;
  }
  require(fs::is_directory(path.parent_path()),
          "Parent directory does not exist: " + utf8(path.parent_path()),
          Code::failure);
#ifdef _WIN32
  Bytes buffer = token_user();
  auto user = reinterpret_cast<TOKEN_USER *>(buffer.data());
  wchar_t *sid = nullptr;
  require(ConvertSidToStringSidW(user->User.Sid, &sid) != 0,
          "Cannot format user SID", Code::failure);
  // An elevated token can default to the Administrators group as owner. Our
  // managed-directory contract requires the actual user SID on every access.
  const std::wstring user_sid(sid);
  const std::wstring sddl =
      L"O:" + user_sid + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user_sid + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
              sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != 0,
          "Cannot create private ACL", Code::failure);
  SECURITY_ATTRIBUTES attrs{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  const bool ok = CreateDirectoryW(path.c_str(), &attrs) != 0;
  LocalFree(descriptor);
  require(ok, "Cannot create private directory: " + utf8(path), Code::failure);
  check_private_acl(path);
#else
  require(mkdirat(parent.back()->value, path.filename().c_str(), 0700) == 0,
          "Cannot create private directory", Code::failure);
  require(fsync(parent.back()->value) == 0, "Cannot sync new directory parent",
          Code::failure);
#endif
}

void remove_owned_tree(const fs::path &path, const fs::path &owner) {
  assert_safe_path(owner, false);
  assert_safe_path(path);
  require(
      fs::absolute(path).parent_path() == fs::absolute(owner) && path != owner,
      "Cleanup outside managed directory rejected");
  if (!fs::exists(path)) return;
  for (const auto &entry : fs::recursive_directory_iterator(path))
    assert_safe_path(entry.path(), false);
  fs::remove_all(path);
  sync_dir(owner);
}

std::string random_id() {
  Bytes random(16);
#ifdef _WIN32
  require(
      BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
      "Random generator failed", Code::failure);
#else
  require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1,
          "Random generator failed", Code::failure);
#endif
  return hex(random);
}

std::string sha256(std::span<const unsigned char> data) {
  Bytes hash(32);
#ifdef _WIN32
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                      nullptr, 0) == 0,
          "Cannot open SHA-256", Code::failure);
  BCRYPT_HASH_HANDLE handle = nullptr;
  auto result = BCryptCreateHash(algorithm, &handle, nullptr, 0, nullptr, 0, 0);
  if (result == 0)
    result = BCryptHashData(handle, const_cast<PUCHAR>(data.data()),
                            static_cast<ULONG>(data.size()), 0);
  if (result == 0) result = BCryptFinishHash(handle, hash.data(), 32, 0);
  if (handle) BCryptDestroyHash(handle);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  require(result == 0, "SHA-256 failed", Code::failure);
#else
  unsigned int length = 0;
  require(EVP_Digest(data.data(), data.size(), hash.data(), &length,
                     EVP_sha256(), nullptr) == 1 &&
              length == 32,
          "SHA-256 failed", Code::failure);
#endif
  return hex(hash);
}

bool verify_signature(std::span<const unsigned char> key,
                      std::span<const unsigned char> signature,
                      std::span<const unsigned char> message, bool rsa) {
#ifdef _WIN32
  CERT_PUBLIC_KEY_INFO *info = nullptr;
  DWORD size = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.data(),
                           static_cast<DWORD>(key.size()),
                           CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &size))
    return false;
  BCRYPT_KEY_HANDLE imported = nullptr;
  const bool ok = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0,
                                              nullptr, &imported) != 0;
  LocalFree(info);
  if (!ok) return false;
  auto hash = unhex(sha256(message));
  Bytes encoded(signature.begin(), signature.end());
  if (!rsa) {
    // CRX uses DER ECDSA signatures; CNG expects fixed-width r || s for P-256.
    std::size_t p = 0;
    encoded.clear();
    if (signature.size() < 8 || signature.size() > 72 ||
        signature[p++] != 0x30 || signature[p++] != signature.size() - 2) {
      BCryptDestroyKey(imported);
      return false;
    }
    for (int i = 0; i < 2; ++i) {
      if (p + 2 > signature.size() || signature[p++] != 2) {
        BCryptDestroyKey(imported);
        return false;
      }
      std::size_t length = signature[p++];
      if (!length || length > 33 || p + length > signature.size() ||
          (signature[p] & 0x80)) {
        BCryptDestroyKey(imported);
        return false;
      }
      if (length > 1 && signature[p] == 0) {
        if (!(signature[p + 1] & 0x80)) {
          BCryptDestroyKey(imported);
          return false;
        }
        ++p;
        --length;
      }
      if (length > 32) {
        BCryptDestroyKey(imported);
        return false;
      }
      encoded.insert(encoded.end(), 32 - length, 0);
      encoded.insert(
          encoded.end(), signature.begin() + static_cast<std::ptrdiff_t>(p),
          signature.begin() + static_cast<std::ptrdiff_t>(p + length));
      p += length;
    }
    if (p != signature.size()) {
      BCryptDestroyKey(imported);
      return false;
    }
  }
  BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
  const auto result = BCryptVerifySignature(
      imported, rsa ? &padding : nullptr, hash.data(), 32, encoded.data(),
      static_cast<ULONG>(encoded.size()), rsa ? BCRYPT_PAD_PKCS1 : 0);
  BCryptDestroyKey(imported);
  return result == 0;
#else
  const unsigned char *pointer = key.data();
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> imported(
      d2i_PUBKEY(nullptr, &pointer, static_cast<long>(key.size())),
      EVP_PKEY_free);
  if (!imported || pointer != key.data() + key.size()) return false;
  if (rsa ? !EVP_PKEY_is_a(imported.get(), "RSA")
          : !EVP_PKEY_is_a(imported.get(), "EC"))
    return false;
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);
  return context &&
         EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr,
                              imported.get()) == 1 &&
         EVP_DigestVerifyUpdate(context.get(), message.data(),
                                message.size()) == 1 &&
         EVP_DigestVerifyFinal(context.get(), signature.data(),
                               signature.size()) == 1;
#endif
}

struct Lock::Impl {
  DirectoryHandles parents;
  Handle file;

  explicit Impl(const fs::path &path)
      : parents(pin_directory(fs::absolute(path).parent_path())),
#ifdef _WIN32
        file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) {
    require(file.value != INVALID_HANDLE_VALUE,
            "Another operation is running or lock is inaccessible",
            Code::failure);
    regular_handle(file.value);
#else
        file(openat(parents.back()->value, path.filename().c_str(),
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                    0600)) {
    require(file.value >= 0, "Cannot open installation lock", Code::failure);
    regular_handle(file.value);
    require(flock(file.value, LOCK_EX | LOCK_NB) == 0,
            "Another operation is running", Code::failure);
#endif
  }
};

Lock::Lock(const fs::path &path) {
  assert_safe_path(path);
  impl_ = std::make_unique<Impl>(path);
}

Lock::~Lock() = default;

fs::path cache_path() {
#ifdef _WIN32
  const auto base = local_app_data();
#else
  auto base = env_path("XDG_CACHE_HOME");
  if (base.empty()) base = env_path("HOME") / ".cache";
#endif
  require(!base.empty() && base.is_absolute(),
          "No absolute user cache directory", Code::failure);
  assert_safe_path(base);
  if (!fs::exists(base)) create_private_dir(base);
  return base / "helium-drm-fixer";
}

fs::path resolve_helium_app(const fs::path &path) {
#ifdef _WIN32
  require(!path.empty(), "Empty Helium application path", Code::invalid);
  const auto root = fs::absolute(path).lexically_normal();
  assert_safe_path(root);
  require(fs::is_directory(root), "Helium application directory not found",
          Code::missing);
  auto version = latest_version_dir(root);
  if (!version) {
    try {
      (void)version_parts(utf8(root.filename()));
      version = root;
    } catch (const Error &) {
      throw Error("No valid Helium version directory found", Code::missing);
    }
  }
  assert_safe_path(*version, false);
  const auto application = *version == root ? root.parent_path() : root;
  const auto executable = fs::is_regular_file(*version / "helium.exe")
                              ? *version / "helium.exe"
                              : application / "helium.exe";
  require(fs::is_regular_file(executable), "Helium executable not found",
          Code::missing);
  validate_binary(read_file(executable, 65536, true), false);
  return *version / "WidevineCdm";
#else
  (void)path;
  throw Error(
      "--helium-app-path is only supported on Windows; use the exact "
      "profile WidevineCdm root with --helium-path on Linux",
      Code::invalid);
#endif
}

fs::path detect_target() {
#ifdef _WIN32
  const auto local = local_app_data();
  std::vector<fs::path> roots;
  if (!local.empty()) {
    roots = {local / "imput" / "Helium" / "Application",
             local / "Helium" / "Application"};
  }
  for (const auto &name : {L"ProgramFiles", L"ProgramFiles(x86)"}) {
    const auto base = env_path(name);
    if (base.empty()) continue;
    require(base.is_absolute(), "Program Files path must be absolute");
    roots.push_back(base / "Helium" / "Application");
  }
  for (const auto &root : roots)
    if (latest_version_dir(root)) return resolve_helium_app(root);
#else
  require(env_path("FLATPAK_ID").empty() && env_path("SNAP").empty(),
          "Sandboxed installs are not supported", Code::missing);
  auto base = env_path("XDG_CONFIG_HOME");
  if (base.empty()) base = env_path("HOME") / ".config";
  require(base.is_absolute(), "No absolute user config directory",
          Code::failure);
  for (const fs::path &candidate :
       {fs::path("/usr/bin/helium"), fs::path("/usr/bin/helium-browser"),
        fs::path("/opt/helium/helium"),
        fs::path("/opt/helium-browser-bin/helium")}) {
    if (fs::exists(candidate)) {
      const auto executable = fs::canonical(candidate);
      validate_binary(read_file(executable, 65536, true), false);
      break;
    }
  }
  std::vector<fs::path> candidates;
  for (const auto &name : {"net.imput.helium", "Helium", "helium"}) {
    const auto profile = base / name;
    if (fs::is_regular_file(profile / "Local State"))
      candidates.push_back(profile / "WidevineCdm");
  }
  require(candidates.size() <= 1,
          "Multiple Helium profiles: specify --helium-path", Code::missing);
  if (candidates.size() == 1) return candidates.front();
#endif
  throw Error(
      "Helium not found. Launch it once or specify the exact WidevineCdm root "
      "with --helium-path",
      Code::missing);
}

fs::path detect_chrome() {
  std::vector<fs::path> roots;
#ifdef _WIN32
  for (const auto &base :
       {env_path(L"ProgramFiles"), env_path(L"ProgramFiles(x86)"),
        env_path(L"LOCALAPPDATA")})
    if (!base.empty())
      roots.push_back(base / "Google" / "Chrome" / "Application");
  for (HKEY hive : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
    wchar_t buffer[2048]{};
    DWORD size = sizeof(buffer);
    if (RegGetValueW(hive,
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App "
                     L"Paths\\chrome.exe",
                     nullptr, RRF_RT_REG_SZ, nullptr, buffer,
                     &size) == ERROR_SUCCESS)
      roots.push_back(fs::path(buffer).parent_path());
  }
#else
  roots = {"/opt/google/chrome", "/opt/google/chrome-beta",
           "/usr/lib/chromium"};
#endif
  for (const auto &root : roots) {
    if (fs::is_regular_file(root / "WidevineCdm" / "manifest.json"))
      return root / "WidevineCdm";
    if (auto latest = latest_version_dir(root))
      if (fs::is_regular_file(*latest / "WidevineCdm" / "manifest.json"))
        return *latest / "WidevineCdm";
  }
  throw Error("Local Chrome CDM not found; specify --chrome-path",
              Code::missing);
}

void ensure_browser_closed() {
#ifdef _WIN32
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  require(snapshot.value != INVALID_HANDLE_VALUE,
          "Cannot inspect running processes", Code::failure);
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  require(Process32FirstW(snapshot.value, &entry) != 0,
          "Cannot inspect running processes", Code::failure);
  do {
    require(_wcsicmp(entry.szExeFile, L"helium.exe") != 0,
            "Close Helium before installing/restoring", Code::failure);
  } while (Process32NextW(snapshot.value, &entry));
#else
  for (const auto &entry : fs::directory_iterator("/proc")) {
    const auto name = entry.path().filename().string();
    if (name.empty() ||
        name.find_first_not_of("0123456789") != std::string::npos)
      continue;
    std::ifstream file(entry.path() / "comm");
    std::string comm;
    if (std::getline(file, comm))
      require(comm != "helium" && comm != "helium-browser",
              "Close Helium before installing/restoring", Code::failure);
  }
#endif
}
}  // namespace fixer
