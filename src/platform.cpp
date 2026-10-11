#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <optional>

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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <sys/file.h>
#include <sys/stat.h>
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
void check_private_acl(const fs::path& path) {
  auto token = token_user();
  auto user = reinterpret_cast<TOKEN_USER*>(token.data())->User.Sid;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  require(GetNamedSecurityInfoW(
              const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
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
    void* pointer = nullptr;
    require(GetAce(dacl, i, &pointer) != 0, "Cannot inspect ACL entry",
            Code::failure);
    const auto header = static_cast<ACE_HEADER*>(pointer);
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    require(header->AceType == ACCESS_ALLOWED_ACE_TYPE,
            "Unsupported managed ACL entry");
    auto ace = static_cast<ACCESS_ALLOWED_ACE*>(pointer);
    auto sid = reinterpret_cast<PSID>(&ace->SidStart);
    require(EqualSid(sid, user) || EqualSid(sid, system),
            "Managed directory permits other users");
  }
}
fs::path env_path(const wchar_t* name) {
  DWORD count = GetEnvironmentVariableW(name, nullptr, 0);
  if (!count) return {};
  std::wstring text(count, L'\0');
  const auto length = GetEnvironmentVariableW(name, text.data(), count);
  require(length && length < count, "Cannot read environment", Code::failure);
  text.resize(length);
  return fs::path(text);
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
}
fs::path env_path(const char* name) {
  auto value = std::getenv(name);
  return value && *value ? fs::path(value) : fs::path{};
}
#endif
std::optional<fs::path> latest_version_dir(const fs::path& root) {
  if (!fs::is_directory(root)) return std::nullopt;
  assert_safe_path(root, false);
  std::optional<fs::path> best;
  std::array<std::uint32_t, 4> best_version{};
  for (const auto& entry : fs::directory_iterator(root)) {
    if (!entry.is_directory()) continue;
    try {
      const auto version = version_parts(utf8(entry.path().filename()));
      if (!best || version > best_version) {
        best = entry.path();
        best_version = version;
      }
    } catch (const Error&) {
      continue;
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
void assert_safe_path(const fs::path& path, bool allow_missing) {
  require(!path.empty(), "Empty path");
  const auto full = fs::absolute(path);
#ifdef _WIN32
  require(full.native().size() <= 240 &&
              full.native().starts_with(full.root_name().native()) &&
              full.root_name().native().size() == 2,
          "Unsupported UNC, device or overlong path");
#endif
  fs::path partial;
  for (const auto& component : full) {
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
Bytes read_file(const fs::path& path, std::size_t limit, bool prefix_only) {
  assert_safe_path(path, false);
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
  Handle file(
      open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
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
void write_file(const fs::path& path, std::span<const unsigned char> data) {
  assert_safe_path(path);
#ifdef _WIN32
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                          nullptr));
  require(file.value != INVALID_HANDLE_VALUE,
          "Cannot exclusively create: " + utf8(path), Code::failure);
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
  Handle file(open(path.c_str(),
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  require(file.value >= 0, "Cannot exclusively create: " + utf8(path),
          Code::failure);
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
void write_text(const fs::path& path, const std::string& text) {
  write_file(
      path, {reinterpret_cast<const unsigned char*>(text.data()), text.size()});
}
void sync_dir(const fs::path& path) {
#ifndef _WIN32
  Handle directory(
      open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  require(directory.value >= 0 && fsync(directory.value) == 0,
          "Cannot sync directory", Code::failure);
#else
  (void)path;  // MoveFileExW uses WRITE_THROUGH; Windows has no general
               // directory fsync API.
#endif
}
void durable_rename(const fs::path& source, const fs::path& dest) {
  assert_safe_path(source, false);
  assert_safe_path(dest);
  require(!fs::exists(dest), "Rename destination already exists");
#ifdef _WIN32
  require(
      MoveFileExW(source.c_str(), dest.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
      "Cannot rename: " + utf8(source), Code::failure);
#else
  require(rename(source.c_str(), dest.c_str()) == 0,
          "Cannot rename: " + utf8(source), Code::failure);
  sync_dir(source.parent_path());
  if (source.parent_path() != dest.parent_path()) sync_dir(dest.parent_path());
#endif
}
void replace_text(const fs::path& path, const std::string& text) {
  assert_safe_path(path);
  const auto temporary =
      path.parent_path() / (utf8(path.filename()) + ".tmp-" + random_id());
  write_text(temporary, text);
  try {
#ifdef _WIN32
    require(
        MoveFileExW(temporary.c_str(), path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0,
        "Cannot replace journal", Code::failure);
#else
    require(rename(temporary.c_str(), path.c_str()) == 0,
            "Cannot replace journal", Code::failure);
    sync_dir(path.parent_path());
#endif
  } catch (...) {
    fs::remove(temporary);
    throw;
  }
}
void create_private_dir(const fs::path& path) {
  assert_safe_path(path);
  if (fs::exists(path)) {
    require(fs::is_directory(path), "Expected a directory");
#ifdef _WIN32
    check_private_acl(path);
#else
    struct stat info{};
    require(lstat(path.c_str(), &info) == 0 && info.st_uid == geteuid() &&
                (info.st_mode & 0077) == 0,
            "Managed directory is not private or not owned by this user");
#endif
    return;
  }
  require(fs::is_directory(path.parent_path()),
          "Parent directory does not exist: " + utf8(path.parent_path()),
          Code::failure);
#ifdef _WIN32
  Bytes buffer = token_user();
  auto user = reinterpret_cast<TOKEN_USER*>(buffer.data());
  wchar_t* sid = nullptr;
  require(ConvertSidToStringSidW(user->User.Sid, &sid) != 0,
          "Cannot format user SID", Code::failure);
  const std::wstring sddl =
      L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
              sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != 0,
          "Cannot create private ACL", Code::failure);
  SECURITY_ATTRIBUTES attrs{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  const bool ok = CreateDirectoryW(path.c_str(), &attrs) != 0;
  LocalFree(descriptor);
  require(ok, "Cannot create private directory: " + utf8(path), Code::failure);
#else
  require(mkdir(path.c_str(), 0700) == 0, "Cannot create private directory",
          Code::failure);
  sync_dir(path.parent_path());
#endif
}
void remove_owned_tree(const fs::path& path, const fs::path& owner) {
  assert_safe_path(owner, false);
  assert_safe_path(path);
  require(
      fs::absolute(path).parent_path() == fs::absolute(owner) && path != owner,
      "Cleanup outside managed directory rejected");
  if (!fs::exists(path)) return;
  for (const auto& entry : fs::recursive_directory_iterator(path))
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
  CERT_PUBLIC_KEY_INFO* info = nullptr;
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
  const unsigned char* pointer = key.data();
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
  Handle file;
  explicit Impl(const fs::path& path)
#ifdef _WIN32
      : file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) {
    require(file.value != INVALID_HANDLE_VALUE,
            "Another operation is running or lock is inaccessible",
            Code::failure);
    regular_handle(file.value);
#else
      : file(open(path.c_str(),
                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                  0600)) {
    require(file.value >= 0, "Cannot open installation lock", Code::failure);
    regular_handle(file.value);
    require(flock(file.value, LOCK_EX | LOCK_NB) == 0,
            "Another operation is running", Code::failure);
#endif
  }
};
Lock::Lock(const fs::path& path) {
  assert_safe_path(path);
  impl_ = std::make_unique<Impl>(path);
}
Lock::~Lock() = default;
fs::path cache_path() {
#ifdef _WIN32
  const auto base = env_path(L"LOCALAPPDATA");
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
fs::path detect_target() {
#ifdef _WIN32
  const auto local = env_path(L"LOCALAPPDATA");
  require(!local.empty(), "LOCALAPPDATA is missing", Code::failure);
  for (const auto& root : {local / "imput" / "Helium" / "Application",
                           local / "Helium" / "Application"}) {
    if (auto latest = latest_version_dir(root)) {
      const auto executable = fs::is_regular_file(root / "helium.exe")
                                  ? root / "helium.exe"
                                  : *latest / "helium.exe";
      require(fs::is_regular_file(executable), "Helium executable not found",
              Code::missing);
      validate_binary(read_file(executable, 65536, true), false);
      return *latest / "WidevineCdm";
    }
  }
#else
  require(env_path("FLATPAK_ID").empty() && env_path("SNAP").empty(),
          "Sandboxed installs are not supported", Code::missing);
  auto base = env_path("XDG_CONFIG_HOME");
  if (base.empty()) base = env_path("HOME") / ".config";
  require(base.is_absolute(), "No absolute user config directory",
          Code::failure);
  for (const fs::path& candidate :
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
  for (const auto& name : {"net.imput.helium", "Helium", "helium"}) {
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
  for (const auto& base :
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
  for (const auto& root : roots) {
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
  for (const auto& entry : fs::directory_iterator("/proc")) {
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
