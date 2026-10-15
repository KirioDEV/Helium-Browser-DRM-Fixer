#include "directory.hpp"

#include <algorithm>
#include <cerrno>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace fixer {
namespace {
fs::path leaf(const std::string &name) {
  require(!name.empty() && name != "." && name != ".." &&
              name.find_first_of("/\\:") == std::string::npos &&
              name.find('\0') == std::string::npos,
          "Expected a single directory entry name");
  return from_utf8(name);
}
#ifndef _WIN32
struct File {
  int fd;
  explicit File(int value) : fd(value) {}
  ~File() {
    if (fd >= 0) close(fd);
  }
  File(const File &) = delete;
  File &operator=(const File &) = delete;
};
struct CloseDirectory {
  void operator()(DIR *directory) const { (void)closedir(directory); }
};
void regular(int fd) {
  struct stat info{};
  require(fd >= 0 && fstat(fd, &info) == 0, "Cannot open transaction file",
          Code::failure);
  require(S_ISREG(info.st_mode) && info.st_nlink == 1,
          "Transaction file is not a regular single-link file");
}
void put(int directory, const std::string &name,
         std::span<const unsigned char> data, bool &created) {
  File file(openat(directory, name.c_str(),
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  require(file.fd >= 0, "Cannot exclusively create transaction file",
          Code::failure);
  created = true;
  regular(file.fd);
  std::size_t position = 0;
  while (position < data.size()) {
    const auto count =
        ::write(file.fd, data.data() + position,
                std::min<std::size_t>(65536, data.size() - position));
    if (count < 0 && errno == EINTR) continue;
    require(count > 0, "Transaction write failed", Code::failure);
    position += static_cast<std::size_t>(count);
  }
  require(fsync(file.fd) == 0, "Cannot flush transaction file", Code::failure);
}
#endif
}  // namespace

struct Directory::Impl {
  fs::path path;
  std::shared_ptr<Impl> parent;
#ifdef _WIN32
  HANDLE handle = INVALID_HANDLE_VALUE;
  Impl(fs::path value, std::shared_ptr<Impl> owner, bool movable)
      : path(std::move(value)), parent(std::move(owner)) {
    handle = CreateFileW(
        path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | (movable ? FILE_SHARE_DELETE : 0),
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(handle != INVALID_HANDLE_VALUE, "Cannot open transaction directory",
            Code::failure);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
      CloseHandle(handle);
      handle = INVALID_HANDLE_VALUE;
      throw Error("Invalid transaction directory", Code::security);
    }
  }
  ~Impl() {
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  }
#else
  int fd = -1;
  Impl(fs::path value, std::shared_ptr<Impl> owner, bool)
      : path(std::move(value)), parent(std::move(owner)) {
    const auto flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    fd = parent ? openat(parent->fd, path.filename().c_str(), flags)
                : open(path.c_str(), flags);
    require(fd >= 0, "Cannot open transaction directory", Code::failure);
  }
  ~Impl() {
    if (fd >= 0) close(fd);
  }
#endif
};

Directory::Directory(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
Directory::Directory(const fs::path &path) {
  assert_safe_path(path, false);
  const auto absolute = fs::absolute(path);
  auto current = absolute.root_path();
  impl_ = std::make_shared<Impl>(current, nullptr, false);
  for (const auto &component : absolute.relative_path()) {
    (void)leaf(utf8(component));
    current /= component;
    impl_ = std::make_shared<Impl>(current, impl_, false);
  }
}
Directory Directory::child(const std::string &name) const {
  return Directory(
      std::make_shared<Impl>(impl_->path / leaf(name), impl_, true));
}
bool Directory::exists(const std::string &name) const {
  (void)leaf(name);
#ifdef _WIN32
  const auto path = impl_->path / from_utf8(name);
  assert_safe_path(path);
  return fs::exists(path);
#else
  struct stat info{};
  if (fstatat(impl_->fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
    require(errno == ENOENT, "Cannot inspect transaction entry", Code::failure);
    return false;
  }
  require(S_ISREG(info.st_mode) || S_ISDIR(info.st_mode),
          "Link or special file in transaction directory");
  return true;
#endif
}
void Directory::create_private(const std::string &name) const {
  (void)leaf(name);
#ifdef _WIN32
  create_private_dir(impl_->path / from_utf8(name));
#else
  if (!exists(name)) {
    require(mkdirat(impl_->fd, name.c_str(), 0700) == 0,
            "Cannot create private transaction directory", Code::failure);
    sync();
  }
  const auto opened = child(name);
  struct stat info{};
  require(fstat(opened.impl_->fd, &info) == 0 && info.st_uid == geteuid() &&
              (info.st_mode & 0077) == 0,
          "Transaction directory is not private or not owned by this user");
#endif
}
Bytes Directory::read(const std::string &name, std::size_t limit) const {
  (void)leaf(name);
#ifdef _WIN32
  return read_file(impl_->path / from_utf8(name), limit);
#else
  File file(openat(impl_->fd, name.c_str(),
                   O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
  regular(file.fd);
  struct stat info{};
  require(fstat(file.fd, &info) == 0 && info.st_size >= 0 &&
              static_cast<std::uint64_t>(info.st_size) <= limit,
          "Transaction file exceeds size limit");
  Bytes bytes(static_cast<std::size_t>(info.st_size));
  std::size_t position = 0;
  while (position < bytes.size()) {
    const auto count =
        ::read(file.fd, bytes.data() + position,
               std::min<std::size_t>(65536, bytes.size() - position));
    if (count < 0 && errno == EINTR) continue;
    require(count > 0, "Transaction read failed", Code::failure);
    position += static_cast<std::size_t>(count);
  }
  return bytes;
#endif
}
void Directory::write(const std::string &name,
                      std::span<const unsigned char> bytes) const {
  (void)leaf(name);
#ifdef _WIN32
  write_file(impl_->path / from_utf8(name), bytes);
#else
  bool created = false;
  put(impl_->fd, name, bytes, created);
#endif
}
void Directory::write_text(const std::string &name,
                           const std::string &text) const {
  write(name,
        {reinterpret_cast<const unsigned char *>(text.data()), text.size()});
}
void Directory::replace(const std::string &name,
                        const std::string &text) const {
  (void)leaf(name);
#ifdef _WIN32
  replace_text(impl_->path / from_utf8(name), text);
#else
  const auto temporary = name + ".tmp-" + random_id();
  bool created = false;
  try {
    put(impl_->fd, temporary,
        {reinterpret_cast<const unsigned char *>(text.data()), text.size()},
        created);
    require(
        renameat(impl_->fd, temporary.c_str(), impl_->fd, name.c_str()) == 0,
        "Cannot replace transaction journal", Code::failure);
    sync();
  } catch (...) {
    if (created) (void)unlinkat(impl_->fd, temporary.c_str(), 0);
    throw;
  }
#endif
}
void Directory::rename(const std::string &name, const Directory &destination,
                       const std::string &destination_name) const {
  (void)leaf(name);
  (void)leaf(destination_name);
  require(exists(name), "Transaction rename source missing", Code::recovery);
#ifdef _WIN32
  durable_rename(impl_->path / from_utf8(name),
                 destination.impl_->path / from_utf8(destination_name));
#else
  require(syscall(SYS_renameat2, impl_->fd, name.c_str(), destination.impl_->fd,
                  destination_name.c_str(), RENAME_NOREPLACE) == 0,
          "Cannot rename transaction entry without replacement", Code::failure);
  sync();
  destination.sync();
#endif
}
std::vector<Directory::Entry> Directory::entries() const {
  std::vector<Entry> result;
#ifdef _WIN32
  for (const auto &entry : fs::directory_iterator(impl_->path)) {
    assert_safe_path(entry.path(), false);
    require(entry.is_directory() || entry.is_regular_file(),
            "Special file in transaction tree");
    result.push_back({utf8(entry.path().filename()), entry.is_directory()});
    require(result.size() <= 1024, "Too many transaction directory entries");
  }
#else
  File fd(openat(impl_->fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  require(fd.fd >= 0, "Cannot enumerate transaction directory", Code::failure);
  DIR *raw = fdopendir(fd.fd);
  require(raw != nullptr, "Cannot enumerate transaction directory",
          Code::failure);
  fd.fd = -1;  // fdopendir owns the descriptor after success.
  std::unique_ptr<DIR, CloseDirectory> stream(raw);
  for (;;) {
    errno = 0;
    const auto entry = readdir(stream.get());
    if (!entry) {
      require(errno == 0, "Cannot read transaction directory", Code::failure);
      break;
    }
    const std::string name = entry->d_name;
    if (name == "." || name == "..") continue;
    (void)leaf(name);
    struct stat info{};
    require(fstatat(impl_->fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0,
            "Cannot inspect transaction tree entry", Code::failure);
    require(S_ISREG(info.st_mode) || S_ISDIR(info.st_mode),
            "Link or special file in transaction tree");
    result.push_back({name, S_ISDIR(info.st_mode)});
    require(result.size() <= 1024, "Too many transaction directory entries");
  }
#endif
  return result;
}
void Directory::sync() const {
#ifndef _WIN32
  require(fsync(impl_->fd) == 0, "Cannot sync transaction directory",
          Code::failure);
#endif
}
void Directory::verify_location() const {
  try {
    const Directory current(impl_->path);
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION expected{}, actual{};
    require(GetFileInformationByHandle(impl_->handle, &expected) &&
                GetFileInformationByHandle(current.impl_->handle, &actual) &&
                expected.dwVolumeSerialNumber == actual.dwVolumeSerialNumber &&
                expected.nFileIndexHigh == actual.nFileIndexHigh &&
                expected.nFileIndexLow == actual.nFileIndexLow,
            "Transaction directory identity changed", Code::recovery);
#else
    struct stat expected{}, actual{};
    require(fstat(impl_->fd, &expected) == 0 &&
                fstat(current.impl_->fd, &actual) == 0 &&
                expected.st_dev == actual.st_dev &&
                expected.st_ino == actual.st_ino,
            "Transaction directory identity changed", Code::recovery);
#endif
  } catch (const Error &) {
    throw Error("Transaction directory path changed; refusing path replacement",
                Code::recovery);
  }
}

struct DirectoryLock::Impl {
  Directory directory;
#ifdef _WIN32
  Lock lock;
  Impl(const Directory &owner, const std::string &name)
      : directory(owner), lock(owner.impl_->path / leaf(name)) {}
#else
  File file;
  Impl(const Directory &owner, const std::string &name)
      : directory(owner),
        file(openat(owner.impl_->fd, leaf(name).c_str(),
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                    0600)) {
    regular(file.fd);
    require(flock(file.fd, LOCK_EX | LOCK_NB) == 0,
            "Another operation is running", Code::failure);
  }
#endif
};
DirectoryLock::DirectoryLock(const Directory &directory,
                             const std::string &name)
    : impl_(std::make_unique<Impl>(directory, name)) {}
DirectoryLock::~DirectoryLock() = default;
std::unique_ptr<DirectoryLock> Directory::lock(const std::string &name) const {
  return std::unique_ptr<DirectoryLock>(new DirectoryLock(*this, name));
}

Json directory_inventory(const Directory &directory) {
  Json files = Json::object();
  std::size_t count = 0, total = 0;
  std::function<void(const Directory &, const std::string &, unsigned)> visit;
  visit = [&](const Directory &current, const std::string &prefix,
              unsigned depth) {
    require(depth <= 32, "Transaction tree exceeds directory depth limit");
    for (const auto &entry : current.entries()) {
      require(++count <= 1024, "Existing CDM has too many entries");
      const auto relative = prefix + entry.name;
      if (entry.directory) {
        visit(current.child(entry.name), relative + "/", depth + 1);
      } else {
        const auto bytes = current.read(entry.name, file_limit);
        require(bytes.size() <= expanded_limit - total,
                "Existing CDM exceeds backup validation limit");
        total += bytes.size();
        files[relative] = sha256(bytes);
      }
    }
  };
  visit(directory, "", 0);
  return files;
}
}  // namespace fixer
