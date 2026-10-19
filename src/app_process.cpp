#include <chrono>
#include <cstdlib>
#include <limits>
#include <sstream>

#include "app_identity.hpp"
#include "app_update.hpp"
#include "directory.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <fstream>

extern char **environ;
#endif

namespace fixer {
namespace {
using Clock = std::chrono::steady_clock;
constexpr auto jobs_name = app_update_jobs_name;
constexpr auto app_name = app_update_binary;
#ifdef _WIN32
constexpr auto helper_name = "update-helper.exe";

struct NativeProcess {
  HANDLE value = nullptr;
  ~NativeProcess() {
    if (value) CloseHandle(value);
  }
};

Json identity(HANDLE process, DWORD pid) {
  FILETIME created{}, exited{}, kernel{}, user{};
  require(GetProcessTimes(process, &created, &exited, &kernel, &user),
          "Cannot read process creation time", Code::failure);
  std::wstring image(32768, L'\0');
  DWORD size = static_cast<DWORD>(image.size());
  require(QueryFullProcessImageNameW(process, 0, image.data(), &size),
          "Cannot read process image path", Code::failure);
  image.resize(size);
  const auto stamp =
      (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) |
      created.dwLowDateTime;
  return {{"pid", pid},
          {"started", std::to_string(stamp)},
          {"image", utf8(fs::path(image).lexically_normal())}};
}

Json self_identity() {
  return identity(GetCurrentProcess(), GetCurrentProcessId());
}

void open_parent(NativeProcess &process, const Json &expected) {
  const auto pid = expected.at("pid").get<std::uint32_t>();
  require(pid != 0 && pid != GetCurrentProcessId(),
          "Invalid update parent PID");
  process.value =
      OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  require(process.value != nullptr, "Cannot pin update parent process",
          Code::failure);
  require(identity(process.value, pid) == expected,
          "Update parent process identity changed");
}

bool exited(const NativeProcess &process, unsigned milliseconds) {
  const auto result = WaitForSingleObject(process.value, milliseconds);
  require(result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT,
          "Cannot wait for update process", Code::failure);
  return result == WAIT_OBJECT_0;
}

std::wstring quote(const std::wstring &value) {
  require(value.find(L'\0') == std::wstring::npos,
          "NUL in helper process argument");
  std::wstring result = L"\"";
  std::size_t slashes = 0;
  for (const auto c : value) {
    if (c == L'\\') {
      ++slashes;
      continue;
    }
    result.append(slashes * (c == L'"' ? 2 : 1), L'\\');
    if (c == L'"') result += L'\\';
    slashes = 0;
    result += c;
  }
  result.append(slashes * 2, L'\\');
  return result + L'"';
}

void launch(NativeProcess &process, const fs::path &helper,
            const fs::path &request) {
  auto command = quote(helper.native()) + L" --internal-app-update " +
                 quote(request.native());
  require(command.size() < 32767, "Helper command line is too long");
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  require(CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr,
                         FALSE, CREATE_NO_WINDOW, nullptr,
                         helper.parent_path().c_str(), &startup, &info),
          "Cannot start app update helper", Code::failure);
  process.value = info.hProcess;
  CloseHandle(info.hThread);
}
#else
constexpr auto helper_name = "update-helper";

struct NativeProcess {
  int value = -1;
  ~NativeProcess() {
    if (value >= 0) close(value);
  }
};

Json identity(pid_t pid) {
  const auto base = "/proc/" + std::to_string(pid);
  std::ifstream input(base + "/stat");
  std::string stat;
  std::getline(input, stat);
  require(!stat.empty() && stat.size() < 16384,
          "Cannot read process start time", Code::failure);
  const auto end = stat.rfind(')');
  require(end != std::string::npos, "Invalid process stat record");
  std::istringstream fields(stat.substr(end + 1));
  std::string field;
  // The command name can contain spaces and ')'. Fields after its final ')'
  // begin at field 3; starttime is field 22.
  for (unsigned number = 3; number <= 22; ++number)
    require(static_cast<bool>(fields >> field), "Missing process start time");
  require(!field.empty() &&
              field.find_first_not_of("0123456789") == std::string::npos,
          "Invalid process start time");
  std::string image(32768, '\0');
  const auto count =
      readlink((base + "/exe").c_str(), image.data(), image.size());
  require(count > 0 && static_cast<std::size_t>(count) < image.size(),
          "Cannot read process image path", Code::failure);
  image.resize(static_cast<std::size_t>(count));
  return {{"pid", pid},
          {"started", field},
          {"image", utf8(from_utf8(image).lexically_normal())}};
}

Json self_identity() { return identity(getpid()); }

#ifdef FIXER_GUI_APP
void copy_gui_libraries(const fs::path &image, const Directory &job) {
  if (!std::getenv("APPIMAGE")) return;
  const auto app = fs::canonical(image.parent_path().parent_path());
  const auto root = fs::canonical(app / "lib");
  const auto inside = root.lexically_relative(app);
  require(!inside.empty() && *inside.begin() != ".." && root != app,
          "AppImage library directory points outside its bundle");
  require(fs::is_directory(root), "AppImage libraries are unavailable");
  job.create_private("lib", true);
  std::size_t total = 0, count = 0;
  std::function<void(const fs::path &, const Directory &, unsigned)> copy;
  copy = [&](const fs::path &source, const Directory &destination,
             unsigned depth) {
    require(depth <= 8, "AppImage library directory is too deep");
    for (const auto &entry : fs::directory_iterator(source)) {
      check_cancelled();
      require(++count <= 512, "Too many AppImage library entries");
      const auto resolved = fs::canonical(entry.path());
      const auto relative = resolved.lexically_relative(root);
      require(!relative.empty() && *relative.begin() != "..",
              "AppImage library points outside its bundle");
      const auto name = validate_entry(utf8(entry.path().filename()));
      if (fs::is_directory(resolved)) {
        destination.create_private(name, true);
        copy(resolved, destination.child(name), depth + 1);
      } else {
        const auto bytes = read_file(resolved, file_limit);
        require(bytes.size() <= expanded_limit - total,
                "AppImage helper libraries exceed size limit");
        total += bytes.size();
        destination.write(name, bytes, false);
        require(destination.read(name, bytes.size()) == bytes,
                "AppImage helper library read-back mismatch");
      }
    }
    destination.sync();
    destination.verify_location();
  };
  copy(root, job.child("lib"), 0);
}

std::vector<std::string> gui_environment(bool restart,
                                         const fs::path &libraries = {}) {
  std::vector<std::string> result;
  for (auto entry = environ; *entry; ++entry) {
    const std::string value(*entry);
    if (value.starts_with("LD_LIBRARY_PATH=")) continue;
    if (restart &&
        (value.starts_with("APPIMAGE=") || value.starts_with("APPDIR=") ||
         value.starts_with("ARGV0=")))
      continue;
    result.push_back(value);
  }
  if (!restart && std::getenv("APPIMAGE")) {
    require(fs::is_directory(libraries), "AppImage libraries are unavailable");
    result.push_back("LD_LIBRARY_PATH=" + utf8(libraries));
  }
  return result;
}
#endif

void open_parent(NativeProcess &process, const Json &expected) {
  const auto pid = expected.at("pid").get<std::uint32_t>();
  require(pid > 0 &&
              pid <= static_cast<unsigned>(std::numeric_limits<pid_t>::max()) &&
              pid != static_cast<unsigned>(getpid()),
          "Invalid update parent PID");
  process.value = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  require(process.value >= 0, "Cannot pin update parent process with pidfd",
          Code::failure);
  require(identity(static_cast<pid_t>(pid)) == expected,
          "Update parent process identity changed");
}

bool exited(const NativeProcess &process, unsigned milliseconds) {
  pollfd descriptor{process.value, POLLIN, 0};
  int result;
  do {
    result = poll(&descriptor, 1, static_cast<int>(milliseconds));
  } while (result < 0 && errno == EINTR);
  require(result >= 0 && !(descriptor.revents & (POLLERR | POLLNVAL)),
          "Cannot wait for update process", Code::failure);
  return result > 0;
}

void launch(NativeProcess &process, const fs::path &helper,
            const fs::path &request) {
  posix_spawn_file_actions_t actions;
  require(posix_spawn_file_actions_init(&actions) == 0,
          "Cannot initialize helper launch", Code::failure);
  struct Cleanup {
    posix_spawn_file_actions_t *value;
    ~Cleanup() { posix_spawn_file_actions_destroy(value); }
  } cleanup{&actions};
  for (int descriptor = 0; descriptor < 3; ++descriptor)
    require(posix_spawn_file_actions_addopen(
                &actions, descriptor, "/dev/null",
                descriptor == 0 ? O_RDONLY : O_WRONLY, 0) == 0,
            "Cannot redirect helper standard streams", Code::failure);
  auto executable = helper.native(), argument = request.native();
  char flag[] = "--internal-app-update";
  char *arguments[]{executable.data(), flag, argument.data(), nullptr};
#ifdef FIXER_GUI_APP
  auto environment = gui_environment(false, helper.parent_path() / "lib");
  std::vector<char *> pointers;
  for (auto &entry : environment) pointers.push_back(entry.data());
  pointers.push_back(nullptr);
  auto child_environment = pointers.data();
#else
  auto child_environment = environ;
#endif
  pid_t pid = 0;
  require(posix_spawn(&pid, helper.c_str(), &actions, nullptr, arguments,
                      child_environment) == 0,
          "Cannot start app update helper", Code::failure);
  process.value = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  require(process.value >= 0, "Cannot pin app update helper", Code::failure);
}
#endif

#ifdef FIXER_GUI_APP
void restart_gui(const fs::path &target, const fs::path &job) {
#ifdef _WIN32
  auto command =
      quote(target.native()) + L" --app-update-result " + quote(job.native());
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  require(
      CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
                     nullptr, target.parent_path().c_str(), &startup, &process),
      "App installed but GUI restart failed", Code::failure);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
#else
  auto executable = target.native();
  char extract[] = "--appimage-extract-and-run";
  char flag[] = "--app-update-result";
  auto result = job.native();
  char *arguments[]{executable.data(), extract, flag, result.data(), nullptr};
  auto environment = gui_environment(true);
  std::vector<char *> pointers;
  for (auto &entry : environment) pointers.push_back(entry.data());
  pointers.push_back(nullptr);
  pid_t child = 0;
  require(posix_spawn(&child, target.c_str(), nullptr, nullptr, arguments,
                      pointers.data()) == 0,
          "App installed but AppImage restart failed", Code::failure);
#endif
}
#endif

Json read_json(const Directory &directory, const std::string &name) {
  const auto bytes = directory.read(name, 16384);
  return parse_json(std::string(bytes.begin(), bytes.end()));
}

void standalone(const VerifiedAppUpdate &update) {
  unsigned executables = 0;
  for (const auto &file : update.files) {
    if (!file.path.starts_with("bin/")) continue;
    require(
        file.path == std::string("bin/") + app_name && file.executable,
        "App self-update requires a standalone package without runtime DLLs");
    ++executables;
  }
  require(executables == 1, "Missing standalone app executable");
}

void target_valid(const fs::path &target) {
  require(target.is_absolute() && target.lexically_normal() == target &&
              target.filename() == app_name &&
              target.parent_path() != target.root_path(),
          "Expected an absolute normalized app target", Code::invalid);
  assert_safe_path(target);
}

Directory open_job(const fs::path &path) {
  require(path.is_absolute() && path.lexically_normal() == path,
          "Expected an absolute normalized app job path");
  const auto name = utf8(path.filename());
  require(name.size() == 36 && name.starts_with("job-") &&
              name.substr(4).find_first_not_of("0123456789abcdef") ==
                  std::string::npos &&
              path.parent_path().filename() == jobs_name,
          "Invalid app update job directory");
  const Directory directory(path);
  assert_private_dir(path);
  assert_private_dir(path.parent_path());
  directory.verify_location();
  return directory;
}

Json read_request(const Directory &job, const fs::path &path) {
  auto request = read_json(job, "request.json");
  try {
    require(request.is_object() &&
                request.size() ==
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
                    9 &&
                request.at("image_sha256").is_string() &&
#else
                    8 &&
#endif
                request.at("format") == 1 &&
                (request.at("operation") == "install" ||
                 request.at("operation") == "restore") &&
                request.at("old_sha256").is_string() &&
                request.at("parent").is_object() &&
                request.at("parent").size() == 3,
            "Invalid app helper request");
    const auto hash = request.at("old_sha256").get<std::string>();
    require(hash.size() == 64 &&
                hash.find_first_not_of("0123456789abcdef") == std::string::npos,
            "Invalid app helper hash");
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
    const auto image_hash = request.at("image_sha256").get<std::string>();
    require(image_hash.size() == 64 &&
                image_hash.find_first_not_of("0123456789abcdef") ==
                    std::string::npos,
            "Invalid native GUI helper hash");
#endif
    const auto target = from_utf8(request.at("target").get<std::string>());
    target_valid(target);
    require(path.parent_path() == target.parent_path() / jobs_name,
            "App helper job does not belong to target");
    const auto image =
        from_utf8(request.at("parent").at("image").get<std::string>());
    require(image.is_absolute() && image.lexically_normal() == image,
            "Invalid app parent image path");
    if (request.at("operation") == "install") {
#if !defined(FIXER_GUI_APP) || defined(_WIN32)
      require(image == target, "App update parent image does not match target");
#endif
      (void)app_version_parts(request.at("version").get<std::string>());
      require(!request.at("directory").get<std::string>().empty(),
              "Missing prepared app directory");
    } else {
      require(request.at("version") == "" && request.at("directory") == "",
              "Unexpected restore request payload");
    }
  } catch (const Json::exception &) {
    throw Error("Malformed app helper request", Code::security);
  }
  return request;
}

void status(const Directory &job, const std::string &phase, int code,
            const std::string &detail) {
  job.verify_location();
  job.replace("status.json", Json{{"schema_version", 1},
                                  {"state", phase},
                                  {"exit_code", code},
                                  {"detail", detail}}
                                 .dump());
}

fs::path schedule(const fs::path &target, const fs::path &directory,
                  const std::string &version, const std::string &expected_hash,
                  bool restore) {
  check_cancelled();
  target_valid(target);
  const auto parent_identity = self_identity();
  const auto image = from_utf8(parent_identity.at("image").get<std::string>());
  const auto bytes = read_file(image, file_limit);
  const auto hash = sha256(bytes);
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
  // Recovery must also work if a crash left only the known backup. The restore
  // transaction validates that backup/journal; it does not install a new ZIP.
  std::string target_hash = hash;
  if (!restore || fs::exists(target)) {
    const auto outer = read_file(target, file_limit);
    if (!restore) validate_app_payload(outer, true);
    target_hash = sha256(outer);
  }
  require(restore || target_hash == expected_hash,
          "AppImage changed during update preparation");
#else
  require(restore || (image == target && hash == expected_hash),
          "Running app image changed during update preparation");
#endif
  const auto root_path = app_update_jobs(target);
  const Directory root(root_path);
  const auto name = "job-" + random_id();
  root.create_private(name, true);
  const auto job_path = root_path / name;
  const auto job = root.child(name);
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
  // The runtime can remove the old AppDir as soon as the GUI exits.
  // Keep helper dependencies in its private job, outside that temporary mount.
  copy_gui_libraries(image, job);
#endif
  job.write(helper_name, bytes, true);
  require(job.read(helper_name, file_limit) == bytes,
          "Helper read-back mismatch");
  Json request{{"format", 1},
               {"operation", restore ? "restore" : "install"},
               {"parent", parent_identity},
               {"target", utf8(target)},
               {"old_sha256", hash},
               {"directory", utf8(directory)},
               {"version", version},
               {"protocol", 1}};
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
  request["image_sha256"] = hash;
  request["old_sha256"] = target_hash;
#endif
  job.write_text("request.json", request.dump());
  job.sync();
  root.verify_location();
  job.verify_location();
  NativeProcess child;
  launch(child, job_path / helper_name, job_path / "request.json");
  try {
    const auto deadline = Clock::now() + std::chrono::seconds(20);
    while (true) {
      check_cancelled();
      job.verify_location();
      if (job.exists("status.json")) {
        const auto response = read_json(job, "status.json");
        require(response.at("state") == "waiting_for_parent",
                "App helper rejected request: " +
                    response.at("detail").get<std::string>(),
                Code::failure);
        break;
      }
      require(
          !exited(child, 50) && Clock::now() < deadline,
          "App helper did not become ready (standalone executable required)",
          Code::failure);
    }
    check_cancelled();
    job.replace("decision.json", Json{{"proceed", true}}.dump());
    job.sync();
    // This is the scheduling commit point: no cancellation after this write.
  } catch (...) {
    // Even a decision write/flush error can leave a visible 'proceed' file.
    // Abort takes precedence and is checked again after the parent has exited.
    job.write_text("abort.json", Json{{"abort", true}}.dump());
    job.sync();
    throw;
  }
  return job_path;
}

template <class Read, class Install>
int helper(const fs::path &request_path, Read read, Install install) {
  require(request_path.filename() == "request.json",
          "Invalid helper request filename");
  const auto path = request_path.parent_path();
  const auto job = open_job(path);
  const auto lock = job.lock("helper.lock");
  require(!job.exists("status.json"), "App update job has already been started",
          Code::recovery);
#ifdef FIXER_GUI_APP
  bool parent_gone = false;
  auto restart_previous = [&] {
    if (!parent_gone || job.exists("abort.json")) return;
    try {
      const auto request = read_request(job, path);
      const auto target = from_utf8(request.at("target").get<std::string>());
      if (sha256(read_file(target, file_limit)) ==
          request.at("old_sha256").get<std::string>())
        restart_gui(target, path);
    } catch (const std::exception &) {
      // Unknown or unrestored files must be preserved for manual recovery.
    }
  };
#endif
  try {
    const auto request = read_request(job, path);
    require(request.at("protocol") == 1, "Unsupported app helper protocol");
    const auto target = from_utf8(request.at("target").get<std::string>());
    const auto current =
        from_utf8(self_identity().at("image").get<std::string>());
    const auto image_hash = request
                                .at(
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
                                    "image_sha256"
#else
                                    "old_sha256"
#endif
                                    )
                                .get<std::string>();
    require(current == path / helper_name &&
                sha256(read_file(current, file_limit)) == image_hash,
            "Helper image is not the expected previous application");
    NativeProcess parent;
    open_parent(parent, request.at("parent"));
    const auto image =
        from_utf8(request.at("parent").at("image").get<std::string>());
    require(sha256(read_file(image, file_limit)) == image_hash,
            "Parent image changed before helper handoff");
    const bool restore = request.at("operation") == "restore";
    const auto staged = from_utf8(request.at("directory").get<std::string>());
    const auto version = request.at("version").get<std::string>();
    if (!restore) standalone(read(staged, version));
    check_cancelled();
    status(job, "waiting_for_parent", 0,
           "Verified; waiting for launch decision and parent exit");
    const auto decision_deadline = Clock::now() + std::chrono::seconds(20);
    while (!job.exists("decision.json")) {
      check_cancelled();
      require(!job.exists("abort.json"), "App update launch was cancelled",
              Code::cancelled);
      const bool parent_exited = exited(parent, 50);
      require(job.exists("decision.json") ||
                  (Clock::now() < decision_deadline && !parent_exited),
              "Parent exited without confirming the app update",
              Code::cancelled);
      job.verify_location();
    }
    require(read_json(job, "decision.json") == Json{{"proceed", true}},
            "App update launch was cancelled", Code::cancelled);
    const auto exit_deadline = Clock::now() + std::chrono::seconds(60);
    while (!exited(parent, 50)) {
      check_cancelled();
      require(!job.exists("abort.json"), "App update launch was cancelled",
              Code::cancelled);
      require(Clock::now() < exit_deadline,
              "App did not exit before update timeout", Code::failure);
    }
#ifdef FIXER_GUI_APP
    parent_gone = true;
#endif
    check_cancelled();
    job.verify_location();
    require(!job.exists("abort.json"), "App update launch was cancelled",
            Code::cancelled);
    status(job, "applying", 0, "Parent exited; applying offline transaction");
    if (restore)
      restore_app_update(target);
    else
      install(staged, version, target,
              request.at("old_sha256").get<std::string>());
    status(job, restore ? "restored" : "installed", 0,
           restore ? "Previous app executable restored"
                   : "Signed app executable installed");
#ifdef FIXER_GUI_APP
    restart_gui(target, path);
#endif
    return 0;
  } catch (const Error &error) {
    status(job, "failed", static_cast<int>(error.code), error.what());
#ifdef FIXER_GUI_APP
    restart_previous();
#endif
    return static_cast<int>(error.code);
  } catch (const std::exception &error) {
    status(job, "failed", 1, error.what());
#ifdef FIXER_GUI_APP
    restart_previous();
#endif
    return 1;
  }
}
}  // namespace

fs::path app_executable_path() {
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
  const auto image = std::getenv("APPIMAGE");
  require(image != nullptr, "Automatic GUI updates require an AppImage",
          Code::invalid);
  const auto target = from_utf8(image);
  target_valid(target);
  return target;
#else
  return from_utf8(self_identity().at("image").get<std::string>());
#endif
}

bool app_self_update_supported() {
#if defined(_WIN32) && !defined(_MSC_VER)
  return false;
#else
#if defined(FIXER_GUI_APP) && !defined(_WIN32)
  try {
    (void)app_executable_path();
  } catch (const std::exception &) {
    return false;
  }
#endif
  return app_update_key_configured();
#endif
}

fs::path app_update_jobs(const fs::path &target) {
  target_valid(target);
  const Directory parent(target.parent_path());
  parent.create_private(jobs_name);
  parent.verify_location();
  return target.parent_path() / jobs_name;
}

fs::path start_app_update(const fs::path &directory, const std::string &version,
                          const std::string &expected_self_sha256) {
  standalone(read_prepared_app_update(directory, version));
  return schedule(app_executable_path(), directory, version,
                  expected_self_sha256, false);
}

fs::path start_app_update_with_trusted_key(
    const fs::path &directory, const std::string &version,
    const std::string &expected_self_sha256,
    std::span<const unsigned char> trusted_key) {
  standalone(read_prepared_app_update_with_trusted_key(directory, version,
                                                       trusted_key));
  return schedule(app_executable_path(), directory, version,
                  expected_self_sha256, false);
}

fs::path start_app_restore(const fs::path &target) {
  return schedule(target, {}, "", "", true);
}

int run_app_update_helper(const fs::path &request) {
  return helper(request, read_prepared_app_update,
                [](const auto &path, const auto &version, const auto &target,
                   const auto &hash) {
                  install_prepared_app_update(path, version, target, hash);
                });
}

int run_app_update_helper_with_trusted_key(
    const fs::path &request, std::span<const unsigned char> trusted_key) {
  return helper(
      request,
      [&](const auto &path, const auto &version) {
        return read_prepared_app_update_with_trusted_key(path, version,
                                                         trusted_key);
      },
      [&](const auto &path, const auto &version, const auto &target,
          const auto &hash) {
        install_prepared_app_update_with_trusted_key(path, version, target,
                                                     hash, trusted_key);
      });
}

Json app_update_job_status(const fs::path &path) {
  const auto job = open_job(path);
  (void)read_request(job, path);
  auto result = read_json(job, "status.json");
  require(result.at("schema_version") == 1 && result.at("state").is_string() &&
              result.at("exit_code").is_number_integer() &&
              result.at("detail").is_string(),
          "Invalid app helper status");
  job.verify_location();
  return result;
}
}  // namespace fixer
