#include <miniz.h>

#include <cstdlib>
#include <iostream>
#include <map>

#include "directory.hpp"
#include "fixer.hpp"
#ifdef _WIN32
// Windows API headers require this include order.
// clang-format off
#include <windows.h>
#include <aclapi.h>
#include <shellapi.h>
// clang-format on
#else
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#endif

using namespace fixer;

namespace {
int assertions = 0;

void expect(bool condition, const std::string &message) {
  ++assertions;
  if (!condition) throw std::runtime_error(message);
}

template <class F>
void rejects(F function, const std::string &message) {
  ++assertions;
  try {
    function();
  } catch (const Error &) {
    return;
  }
  throw std::runtime_error("Did not reject: " + message);
}

Cdm fixture(const std::string &version) {
  Cdm cdm;
  cdm.version = version;
  const auto manifest = Json{{"version", version}}.dump();
  cdm.manifest.assign(manifest.begin(), manifest.end());
  cdm.library.assign(128, 0);
#ifdef _WIN32
  cdm.library[0] = 'M';
  cdm.library[1] = 'Z';
  cdm.library[0x3c] = 64;
  cdm.library[64] = 'P';
  cdm.library[65] = 'E';
  cdm.library[68] = 0x64;
  cdm.library[69] = 0x86;
  cdm.library[87] = 0x20;
  cdm.library[88] = 0x0b;
  cdm.library[89] = 0x02;
#else
  cdm.library[0] = 0x7f;
  cdm.library[1] = 'E';
  cdm.library[2] = 'L';
  cdm.library[3] = 'F';
  cdm.library[4] = 2;
  cdm.library[5] = 1;
  cdm.library[6] = 1;
  cdm.library[16] = 3;
  cdm.library[18] = 62;
#endif
  return cdm;
}

Bytes make_zip(const std::vector<std::pair<std::string, Bytes> > &entries) {
  mz_zip_archive zip{};
  require(mz_zip_writer_init_heap(&zip, 0, 0) != 0, "Cannot create test ZIP");
  for (const auto &[name, bytes] : entries)
    require(mz_zip_writer_add_mem(&zip, name.c_str(), bytes.data(),
                                  bytes.size(), MZ_DEFAULT_COMPRESSION) != 0,
            "Cannot add fixture");
  void *data = nullptr;
  std::size_t size = 0;
  require(mz_zip_writer_finalize_heap_archive(&zip, &data, &size) != 0,
          "Cannot finalize fixture");
  Bytes out(static_cast<unsigned char *>(data),
            static_cast<unsigned char *>(data) + size);
  mz_free(data);
  mz_zip_writer_end(&zip);
  return out;
}

Json snapshot(const fs::path &root) {
  Json out = Json::object();
  for (const auto &entry : fs::recursive_directory_iterator(root)) {
    if (entry.is_regular_file())
      out[utf8(entry.path().lexically_relative(root))] =
          sha256(read_file(entry.path(), package_limit));
    else
      out[utf8(entry.path().lexically_relative(root))] = "directory";
  }
  return out;
}

void directory_tests(const fs::path &root) {
  const Directory parent(root);
  parent.create_private("directory-api");
  const auto directory = parent.child("directory-api");
  directory.write_text("data", "original");
  const auto bytes = directory.read("data", 64);
  expect(std::string(bytes.begin(), bytes.end()) == "original",
         "Anchored read/write");
  expect(directory.entries().size() == 1 && directory.entries().size() == 1,
         "Independent directory enumeration offsets");
  expect(directory_inventory(directory) == Json{{"data", sha256(bytes)}},
         "Anchored inventory");
  for (const auto &name :
       {"", ".", "..", "../data", "sub/file", "sub\\file", "C:data"}) {
    rejects([&] { (void)directory.read(name, 64); }, "Anchored read traversal");
    rejects([&] { directory.write_text(name, "unexpected"); },
            "Anchored write traversal");
  }
  {
    const auto lock = directory.lock("test.lock");
    rejects([&] { (void)directory.lock("test.lock"); },
            "Anchored concurrent lock");
  }
  directory.create_private("child");
  rejects([&] { directory.replace("child", "invalid journal"); },
          "Anchored journal cannot replace directory");
  expect(directory.entries().size() == 3,
         "Anchored journal failure left temporary file");
#ifndef _WIN32
  const auto original = root / "directory-api";
  const auto displaced = root / "displaced-api";
  const auto before_move = directory_inventory(directory);
  fs::rename(original, displaced);
  create_private_dir(original);
  write_text(original / "sentinel", "replacement");
  const auto replacement = snapshot(original);
  rejects([&] { directory.verify_location(); }, "Changed directory identity");
  expect(directory_inventory(directory) == before_move,
         "Inventory reopened a replacement directory");
  directory.replace("data", "anchored update");
  expect(snapshot(original) == replacement,
         "Anchored journal wrote into replacement directory");
  const auto updated = directory.read("data", 64);
  expect(std::string(updated.begin(), updated.end()) == "anchored update",
         "Anchored journal did not update original directory");
  {
    const auto first = directory.lock("test.lock");
    rejects([&] { (void)directory.lock("test.lock"); },
            "Renamed directory lost lock identity");
  }
  fs::create_symlink(original / "sentinel", displaced / "link");
  rejects([&] { (void)directory_inventory(directory); },
          "Anchored inventory followed link");
  fs::remove(displaced / "link");
#endif
}

#ifdef _WIN32
void private_owner_tests(const fs::path &root) {
  const auto path = root / "explicit-user-owner";
  create_private_dir(path);
  struct Token {
    HANDLE value = nullptr;
    ~Token() {
      if (value) CloseHandle(value);
    }
  } token;
  require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != 0,
          "Cannot open test process token");
  DWORD size = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
  Bytes user(size);
  require(GetTokenInformation(token.value, TokenUser, user.data(), size,
                              &size) != 0,
          "Cannot read test user SID");
  PSID owner = nullptr;
  PACL dacl = nullptr;
  struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    ~Descriptor() {
      if (value) LocalFree(value);
    }
  } descriptor;
  require(GetNamedSecurityInfoW(
              const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT,
              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
              nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS,
          "Cannot inspect test directory security");
  expect(
      owner && EqualSid(owner,
                        reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid),
      "New directory owner must be TokenUser, not the token default owner");
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  expect(GetSecurityDescriptorControl(descriptor.value, &control, &revision) &&
             (control & SE_DACL_PROTECTED) && dacl,
         "Private directory must retain a protected DACL");
  create_private_dir(path);
  expect(fs::is_empty(path), "Reopening private directory changed contents");
}
#endif

#ifndef _WIN32
// This deliberately consumes real blocks on a dedicated, bounded tmpfs. Never
// run it on an ordinary profile or build filesystem.
void fill_test_filesystem(const fs::path &path, std::uintmax_t leave) {
  const int fd =
      open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  expect(fd >= 0, "Cannot create disk-space fixture");
  struct Close {
    int fd;
    ~Close() { close(fd); }
  } close_file{fd};
  const Bytes block(4096, 'x');
  bool enospc = false;
  for (std::size_t count = 0; count < 8192; ++count) {
    if (leave && fs::space(path.parent_path()).available <= leave) break;
    const auto written = write(fd, block.data(), block.size());
    if (written < 0) {
      if (errno == EINTR) continue;
      expect(errno == ENOSPC, "Filler failed for a reason other than ENOSPC");
      enospc = true;
      break;
    }
    expect(written > 0, "Filler write made no progress");
  }
  expect(leave ? fs::space(path.parent_path()).available <= leave : enospc,
         "Failed to exhaust bounded test filesystem");
}

void transaction_space_tests(const fs::path &parent) {
  struct statfs filesystem{};
  expect(statfs(parent.c_str(), &filesystem) == 0 &&
             filesystem.f_type == TMPFS_MAGIC && fs::is_empty(parent),
         "Transaction space tests require an empty, dedicated tmpfs");
  const auto space = fs::space(parent);
  expect(
      space.capacity <= 16 * 1024 * 1024 && space.available >= 2 * 1024 * 1024,
      "Transaction space tests require a dedicated 2-16 MiB filesystem");
  unsigned scenarios = 0;
  for (const bool had_old : {false, true}) {
    for (const bool restoring : {false, true}) {
      const std::vector<std::string> phases =
          restoring ? std::vector<std::string>{"restore_validated",
                                               "restore_current_moved",
                                               "restore_backup_moved"}
                    : std::vector<std::string>{"staging",     "prepared",
                                               "old_renamed", "old_moved",
                                               "new_renamed", "new_moved"};
      for (const auto &phase : phases) {
        const auto root = parent / ("transaction-space-" + random_id());
        create_private_dir(root);
        struct Cleanup {
          fs::path root;
          ~Cleanup() {
            std::error_code ignored;
            fs::remove_all(root, ignored);
          }
        } cleanup{root};
        const auto target = root / "WidevineCdm";
        if (had_old) install_cdm(target, fixture("1.2.3.4"));
        const auto old_files = had_old ? snapshot(target) : Json::object();
        auto replacement = fixture("2.0.0.0");
        replacement.library.resize(256 * 1024);
        if (restoring) install_cdm(target, replacement);
        const auto filler = root / "filler";
        bool injected = false, failed = false;
        Code result = Code::failure;
        const InstallHooks hooks{{[&](const std::string &current) {
          if (current != phase || injected) return;
          fill_test_filesystem(filler, phase == "staging" ? 64 * 1024 : 0);
          injected = true;
        }}};
        try {
          if (restoring)
            restore_cdm(target, hooks);
          else
            install_cdm(target, replacement, hooks);
        } catch (const Error &error) {
          failed = true;
          result = error.code;
        }
        expect(injected && failed,
               "Disk-full transaction did not fail: " + phase);
        expect(result == (phase == "staging" ? Code::failure
                          : restoring        ? Code::failure
                                             : Code::recovery),
               "Wrong disk-full error classification: " + phase);
        fs::remove(filler);
        const auto state = root / ".helium-drm-fixer";
        if (phase == "staging") {
          expect(!has_transaction(target), "Failed stage published a journal");
          expect(had_old ? snapshot(target) == old_files : !fs::exists(target),
                 "Failed stage changed original installation");
          bool partial_binary = false;
          for (const auto &entry : fs::recursive_directory_iterator(state)) {
            if (entry.path().filename() == binary_name())
              partial_binary =
                  fs::file_size(entry.path()) < replacement.library.size();
          }
          expect(partial_binary, "Staging test did not leave a partial write");
          install_cdm(target, replacement);
          restore_cdm(target);
          expect(had_old ? snapshot(target) == old_files : !fs::exists(target),
                 "Failed stage prevented a subsequent installation/restore");
        } else {
          expect(has_transaction(target) ==
                     !(restoring && phase == "restore_validated"),
                 "Wrong persisted transaction state after ENOSPC: " + phase);
          const auto journal_bytes =
              read_file(state / "journal.json", 1024 * 1024);
          const auto journal = parse_json(
              std::string(journal_bytes.begin(), journal_bytes.end()));
          if (had_old) {
            const auto backup =
                state / ("backup-" + journal["id"].get<std::string>());
            expect((fs::exists(target) && snapshot(target) == old_files) ||
                       (fs::exists(backup) && snapshot(backup) == old_files),
                   "Disk-full failure lost original files");
          }
          restore_cdm(target);
          restore_cdm(target);
          expect(!has_transaction(target),
                 "Recovery did not finish after freeing space");
          expect(had_old ? snapshot(target) == old_files : !fs::exists(target),
                 "Recovery after ENOSPC did not restore original state");
          const auto id = journal["id"].get<std::string>();
          const auto staged = state / ("stage-" + id);
          const auto reverted = state / ("reverted-" + id);
          const auto preserved = fs::exists(staged) ? staged : reverted;
          expect(
              directory_inventory(Directory(preserved)) == journal["new_files"],
              "Recovery after ENOSPC lost the replacement files");
        }
        for (const auto &entry : fs::directory_iterator(state))
          expect(
              utf8(entry.path().filename()).find(".tmp-") == std::string::npos,
              "Disk-full journal left a temporary file");
        ++scenarios;
      }
    }
  }
  std::cout << scenarios
            << " real ENOSPC staging/installation/recovery scenarios passed\n";
}

void transaction_binding_tests(const fs::path &root) {
  unsigned index = 0;
  for (const bool restoring : {false, true}) {
    const std::vector<std::string> phases =
        restoring
            ? std::vector<std::string>{"restore_validated",
                                       "restore_current_moved",
                                       "restore_backup_moved"}
            : std::vector<std::string>{"prepared", "old_renamed", "old_moved",
                                       "new_renamed", "new_moved"};
    for (const bool replace_parent : {true, false}) {
      for (const auto &phase : phases) {
        const auto test =
            root / ("transaction-binding-" + std::to_string(++index));
        create_private_dir(test);
        const auto profile = test / "profile";
        create_private_dir(profile);
        const auto target = profile / "WidevineCdm";
        install_cdm(target, fixture("1.2.3.4"));
        if (restoring) install_cdm(target, fixture("2.0.0.0"));
        const auto original =
            replace_parent ? profile : profile / ".helium-drm-fixer";
        const auto displaced = replace_parent ? test / "original-profile"
                                              : profile / "original-state";
        Json replacement;
        bool injected = false, rejected = false;
        const InstallHooks hooks{{[&](const std::string &current) {
          if (current != phase) return;
          fs::rename(original, displaced);
          if (replace_parent) {
            create_private_dir(profile);
            install_cdm(target, fixture("9.9.9.9"));
          } else {
            fs::copy(displaced, original, fs::copy_options::recursive);
          }
          replacement = snapshot(original);
          injected = true;
        }}};
        try {
          if (restoring)
            restore_cdm(target, hooks);
          else
            install_cdm(target, fixture("2.0.0.0"), hooks);
        } catch (const Error &error) {
          rejected = error.code == Code::recovery;
        }
        expect(injected && rejected, "Directory replacement was not detected");
        expect(snapshot(original) == replacement,
               "Rollback changed replacement directory or its journal");
        const auto preserved = test / "untouched-replacement";
        fs::rename(original, preserved);
        fs::rename(displaced, original);
        if (restoring) restore_cdm(target);
        expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
               "Rollback did not restore original installation through "
               "anchored directories");
        expect(!has_transaction(target), "Anchored rollback remains pending");
      }
    }
  }
}
#endif
}  // namespace
int main(int argc, char **argv) {
  try {
#ifdef _WIN32
    int count = 0;
    struct Arguments {
      LPWSTR *value;
      ~Arguments() {
        if (value) LocalFree(value);
      }
    } wide{CommandLineToArgvW(GetCommandLineW(), &count)};
    require(wide.value && count > 0, "Cannot read test command line",
            Code::failure);
    std::vector<std::string> utf8_arguments;
    for (int i = 0; i < count; ++i)
      utf8_arguments.push_back(utf8(fs::path(wide.value[i])));
    std::vector<char *> argument_pointers;
    for (auto &argument : utf8_arguments)
      argument_pointers.push_back(argument.data());
    argument_pointers.push_back(nullptr);
    argc = count;
    argv = argument_pointers.data();
#endif
#ifndef _WIN32
    if (argc == 3 && std::string(argv[1]) == "--transaction-space") {
      transaction_space_tests(fs::absolute(from_utf8(argv[2])));
      return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--permission-denied") {
      expect(geteuid() != 0,
             "Permission test must run as an unprivileged user");
      const auto root =
          fs::absolute(fs::temp_directory_path() /
                       ("helium-fixer-permission-test-" + random_id()));
      create_private_dir(root);
      fs::permissions(root, fs::perms::owner_read | fs::perms::owner_exec);
      bool permission_failure = false;
      try {
        install_cdm(root / "WidevineCdm", fixture("1.2.3.4"));
      } catch (const Error &error) {
        permission_failure = error.code == Code::failure;
      }
      fs::permissions(root, fs::perms::owner_all);
      expect(permission_failure,
             "Installation ignored missing write permissions");
      expect(fs::is_empty(root), "Permission failure changed target parent");
      fs::remove(root);
      std::cout << "Real unprivileged write-permission failure passed\n";
      return 0;
    }
#endif
    if (argc == 3 && std::string(argv[1]) == "--low-space") {
      const auto parent = fs::absolute(from_utf8(argv[2]));
      expect(fs::space(parent).available <= 64 * 1024,
             "Low-space test requires a filesystem with at most 64 KiB free");
      const auto root = parent / ("helium-fixer-space-test-" + random_id());
      create_private_dir(root);
      bool failed_for_space = false;
      try {
        install_cdm(root / "WidevineCdm", fixture("1.2.3.4"));
      } catch (const Error &error) {
        failed_for_space =
            error.code == Code::failure &&
            std::string(error.what()) == "Insufficient free space";
      }
      expect(failed_for_space,
             "Installation did not reject insufficient space");
      expect(fs::is_empty(root),
             "Insufficient space created transaction files");
      write_text(root / "journal.json", "original journal");
      const auto before_write_failure = snapshot(root);
      rejects(
          [&] {
            replace_text(root / "journal.json", std::string(128 * 1024, 'x'));
          },
          "Journal write must report real ENOSPC");
      expect(snapshot(root) == before_write_failure,
             "Failed journal write changed original or left a partial "
             "temporary file");
      {
        const Directory directory(root);
        rejects(
            [&] {
              directory.replace("journal.json", std::string(128 * 1024, 'x'));
            },
            "Anchored journal write must report real ENOSPC");
        expect(
            snapshot(root) == before_write_failure,
            "Anchored journal write changed original or left a temporary file");
      }
      fs::remove(root / "journal.json");
      fs::remove(root);
      std::cout
          << "Real low-space preflight and ENOSPC journal cleanup passed\n";
      return 0;
    }
    if (argc == 4 && std::string(argv[1]) == "--crash") {
      const auto target = fs::absolute(from_utf8(argv[2]));
      install_cdm(target, fixture("1.2.3.4"));
      install_cdm(target, fixture("2.3.4.5"), {{[&](const std::string &phase) {
                    if (phase == argv[3]) std::_Exit(77);
                  }}});
      return 1;
    }
    if (argc == 3 && std::string(argv[1]) == "--recover") {
      const auto target = fs::absolute(from_utf8(argv[2]));
      restore_cdm(target);
      expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
             "Crash recovery failed");
      expect(!has_transaction(target), "Recovery remains pending");
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--verify-package") {
      auto bytes = read_file(from_utf8(argv[2]), package_limit);
      const auto cdm = verify_crx(bytes, sha256(bytes));
      bytes.back() ^= 1;
      rejects([&] { (void)verify_crx(bytes); },
              "Tampered real package signature");
      std::cout << "Verified real package " << cdm.version
                << "; tampered copy rejected\n";
      return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--network-probe") {
      const auto release = latest_release();
      const auto bytes = http_request(release.url, "", package_limit);
      const auto cdm = verify_crx(bytes, release.checksum);
      expect(cdm.version == release.version,
             "Real network package version mismatch");
      std::cout << "Real HTTPS -> SHA-256 -> CRX3 -> CDM verification passed: "
                << cdm.version << '\n';
      return 0;
    }
    expect(version_parts("2.0.0.0") > version_parts("1.99.0.0"),
           "Numeric version order");
    for (const auto &v : {"", "1.2.3", "1.2.3.4.5", "../x", "1.-2.3.4",
                          "4294967296.0.0.0", "1.2.3.4/evil"})
      rejects([&] { (void)version_parts(v); }, v);
    expect(
        sha256(Bytes{'a', 'b', 'c'}) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 known answer");
    rejects([] { (void)unhex(std::string(64, 'z')); }, "Invalid hash");
    rejects([] { (void)parse_json("{\"a\":1,\"a\":2}"); },
            "Duplicate JSON key");
    expect(parse_json("{\"a\":{\"b\":1},\"c\":{\"b\":2}}")["c"]["b"] == 2,
           "Object key scope");
    rejects(
        [] {
          (void)parse_json(std::string(40, '[') + "0" + std::string(40, ']'));
        },
        "JSON depth");
    rejects([] { (void)parse_options({"--check", "--dry-run"}); },
            "Conflicting modes");
    rejects([] { (void)parse_options({"--force-download", "--check"}); },
            "Writes in check mode");
    rejects([] { (void)parse_options({"--helium-path"}); }, "Missing value");
    rejects([] { (void)parse_options({"--wat"}); }, "Unknown option");
    rejects([] { (void)parse_options({"--chrome-path", "x"}); },
            "Implicit untrusted source");
    for (const auto &name :
         {"../evil", "/evil", "C:/evil", "foo\\bar", "a/../b", "a//b", "a/./b",
          "a. ", "CON.txt", "dir/aux", "x:stream", "x\n"})
      rejects([&] { (void)validate_entry(name); }, name);
    expect(validate_entry("_platform_specific/win_x64/widevinecdm.dll") ==
               "_platform_specific/win_x64/widevinecdm.dll",
           "Valid archive path");
    for (const auto &url :
         {"http://dl.google.com/a", "https://dl.google.com.evil/a",
          "https://dl.google.com@evil/a", "https://127.0.0.1/a",
          "https://dl.google.com:443/a", "https://dl.google.com/a#x"})
      rejects([&] { (void)validate_url(url); }, url);
    expect(validate_url("https://dl.google.com/a").host == "dl.google.com",
           "Approved HTTPS host");
    int requests = 0;
    for (const auto &redirect :
         {"http://dl.google.com/a", "https://evil.example/a",
          "https://127.0.0.1/a"}) {
      requests = 0;
      rejects(
          [&] {
            (void)request_with_transport(
                "https://dl.google.com/a", "", 1024, false,
                [&](const Url &, const std::string &, std::size_t) {
                  ++requests;
                  return HttpResponse{302, {}, redirect};
                });
          },
          "Unsafe redirect");
      expect(requests == 1, "Unsafe redirect was contacted");
    }
    rejects(
        [] {
          (void)request_with_transport(
              "https://dl.google.com/a", "", 16, false,
              [](const Url &, const std::string &, std::size_t) {
                return HttpResponse{200, Bytes(17), {}};
              });
        },
        "Unknown-length oversized response");
    requests = 0;
    rejects(
        [&] {
          (void)request_with_transport(
              "https://dl.google.com/a", "", 1024, false,
              [&](const Url &, const std::string &, std::size_t) {
                ++requests;
                return HttpResponse{302, {}, "/loop"};
              });
        },
        "Redirect loop");
    expect(requests == 4, "Redirect budget");
    requests = 0;
    expect(request_with_transport(
               "https://dl.google.com/a", "", 1024, false,
               [&](const Url &, const std::string &, std::size_t) {
                 ++requests;
                 return requests == 1 ? HttpResponse{302, {}, "/b"}
                                      : HttpResponse{200, Bytes{42}, {}};
               }) == Bytes{42},
           "Valid relative redirect");
    expect(public_ipv4(Bytes{8, 8, 8, 8}), "Public IPv4");
    for (const auto &address :
         {Bytes{127, 0, 0, 1}, Bytes{10, 0, 0, 1}, Bytes{192, 168, 1, 1},
          Bytes{169, 254, 0, 1}, Bytes{224, 0, 0, 1}, Bytes{100, 64, 0, 1}})
      expect(!public_ipv4(address), "Private/special IPv4 allowed");
    Bytes ipv6(16, 0);
    ipv6[0] = 0x20;
    ipv6[1] = 1;
    ipv6[2] = 0x48;
    ipv6[3] = 0x60;
    expect(public_ipv6(ipv6), "Public IPv6");
    ipv6[0] = 0xfc;
    expect(!public_ipv6(ipv6), "Private IPv6 allowed");
    Json update{
        {"response",
         {{"protocol", "4.0"},
          {"apps",
           Json::array(
               {{{"appid", app_id},
                 {"status", "ok"},
                 {"updatecheck",
                  {{"status", "ok"},
                   {"nextversion", "1.2.3.4"},
                   {"pipelines",
                    Json::array(
                        {{{"operations",
                           Json::array(
                               {{{"type", "download"},
                                 {"size", 100U},
                                 {"out", {{"sha256", std::string(64, 'a')}}},
                                 {"urls",
                                  Json::array(
                                      {{{"url", "http://dl.google.com/a"}},
                                       {{"url", "https://dl.google.com/a"}}})}},
                                {{"type", "crx3"},
                                 {"in",
                                  {{"sha256",
                                    std::string(64, 'a')}}}}})}}})}}}}})}}}};
    expect(parse_release(update.dump()).version == "1.2.3.4",
           "Google metadata parsing");
    auto missing_hash = update;
    missing_hash["response"]["apps"][0]["updatecheck"]["pipelines"][0]
                ["operations"][0]["out"]
                    .erase("sha256");
    rejects([&] { (void)parse_release(missing_hash.dump()); },
            "Missing metadata checksum");
    auto wrong_app = update;
    wrong_app["response"]["apps"][0]["appid"] = "evil";
    rejects([&] { (void)parse_release(wrong_app.dump()); }, "Wrong update app");
    auto mismatch = update;
    mismatch["response"]["apps"][0]["updatecheck"]["pipelines"][0]["operations"]
            [1]["in"]["sha256"] = std::string(64, 'b');
    rejects([&] { (void)parse_release(mismatch.dump()); },
            "Mismatched pipeline hash");
    const auto cdm = fixture("1.2.3.4");
    validate_binary(cdm.library);
    auto invalid = cdm.library;
    invalid[0] = 0;
    rejects([&] { validate_binary(invalid); }, "Invalid binary header");
    auto executable = cdm.library;
#ifdef _WIN32
    executable[87] = 0;
#else
    executable[16] = 2;
#endif
    rejects([&] { validate_binary(executable); },
            "Executable must not be accepted as CDM library");
    validate_binary(executable, false);
    const auto zip = make_zip(
        {{"manifest.json", cdm.manifest}, {binary_name(), cdm.library}});
    expect(extract_zip(zip).version == cdm.version, "ZIP extraction");
    rejects(
        [&] {
          (void)extract_zip(make_zip({{"manifest.json", cdm.manifest},
                                      {binary_name(), cdm.library},
                                      {"../escape", {1}}}));
        },
        "ZIP traversal");
    rejects(
        [&] {
          (void)extract_zip(make_zip({{"manifest.json", cdm.manifest},
                                      {"MANIFEST.JSON", cdm.manifest},
                                      {binary_name(), cdm.library}}));
        },
        "ZIP case collision");
    rejects(
        [&] { (void)extract_zip(make_zip({{"manifest.json", cdm.manifest}})); },
        "Missing library");
    rejects([&] { (void)verify_crx(zip); }, "Unsigned ZIP");
    Bytes crx{'C', 'r', '2', '4', 3, 0, 0, 0, 255, 255, 255, 255};
    crx.insert(crx.end(), zip.begin(), zip.end());
    rejects([&] { (void)verify_crx(crx); }, "CRX length overflow");
    rejects([&] { (void)verify_crx(crx, std::string(64, '0')); },
            "Wrong checksum");

    const auto root = fs::absolute(fs::temp_directory_path() /
                                   ("helium-fixer-test-" + random_id()));
    create_private_dir(root);
    directory_tests(root);
#ifdef _WIN32
    private_owner_tests(root);
#endif
#ifndef _WIN32
    transaction_binding_tests(root);
#endif
    const auto target = root / "WidevineCdm";
    write_file(root / "prefix-test", Bytes(128, 7));
    rejects([&] { (void)read_file(root / "prefix-test", 64); },
            "Oversized local file");
    expect(read_file(root / "prefix-test", 64, true).size() == 64,
           "Bounded header read");
    fs::create_hard_link(root / "prefix-test", root / "hardlink-test");
    rejects([&] { (void)read_file(root / "hardlink-test", 128); },
            "Hardlink alias read");
    rejects([&] { (void)read_file(root / "prefix-test", 128); },
            "Hardlink original read");
    fs::remove(root / "hardlink-test");
    const auto rename_root = root / "rename-tests";
    create_private_dir(rename_root);
    const auto collision_source = rename_root / "source";
    const auto collision_dest = rename_root / "destination";
    write_text(collision_source, "source contents");
    rejects(
        [&] {
          durable_rename(collision_source, collision_dest, [&] {
            write_text(collision_dest, "concurrent contents");
          });
        },
        "Concurrent rename destination file");
    expect(read_file(collision_source, 128) ==
               Bytes({'s', 'o', 'u', 'r', 'c', 'e', ' ', 'c', 'o', 'n', 't',
                      'e', 'n', 't', 's'}),
           "Concurrent rename preserved source file");
    expect(read_file(collision_dest, 128) ==
               Bytes({'c', 'o', 'n', 'c', 'u', 'r', 'r', 'e', 'n', 't', ' ',
                      'c', 'o', 'n', 't', 'e', 'n', 't', 's'}),
           "Concurrent rename preserved destination file");
    const auto source_tree = rename_root / "source-tree";
    const auto dest_tree = rename_root / "destination-tree";
    create_private_dir(source_tree);
    rejects(
        [&] {
          durable_rename(source_tree, dest_tree,
                         [&] { create_private_dir(dest_tree); });
        },
        "Concurrent empty destination directory");
    expect(fs::is_directory(source_tree) && fs::is_directory(dest_tree),
           "Concurrent empty directory was replaced");
    const auto before_failed_journal = snapshot(rename_root);
    rejects([&] { replace_text(dest_tree, "journal contents"); },
            "Journal replacement must not replace a directory");
    expect(
        snapshot(rename_root) == before_failed_journal,
        "Failed journal replacement left a temporary file or changed contents");
    {
      struct RestoreDirectory {
        fs::path original = fs::current_path();
        ~RestoreDirectory() { fs::current_path(original); }
      } restore_directory;
      fs::current_path(rename_root);
      write_text("relative-file", "relative contents");
      durable_rename("relative-file", "relative-renamed");
      replace_text("relative-renamed", "updated");
      const auto bytes = read_file("relative-renamed", 128);
      expect(std::string(bytes.begin(), bytes.end()) == "updated",
             "Relative file and directory-handle operations");
    }
    const auto source_parent = rename_root / "source-parent";
    const auto dest_parent = rename_root / "destination-parent";
    const auto moved_source_parent = rename_root / "original-source";
    const auto moved_dest_parent = rename_root / "original-destination";
    create_private_dir(source_parent);
    create_private_dir(dest_parent);
    write_text(source_parent / "payload", "original");
#ifdef _WIN32
    bool source_rename_blocked = false, dest_rename_blocked = false;
    durable_rename(source_parent / "payload", dest_parent / "payload", [&] {
      std::error_code error;
      fs::rename(source_parent, moved_source_parent, error);
      source_rename_blocked = static_cast<bool>(error);
      error.clear();
      fs::rename(dest_parent, moved_dest_parent, error);
      dest_rename_blocked = static_cast<bool>(error);
    });
    expect(source_rename_blocked && dest_rename_blocked,
           "Pinned Windows parents could be renamed");
    expect(read_file(dest_parent / "payload", 128) ==
               Bytes({'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'}),
           "Pinned Windows rename lost contents");
#else
    const auto redirected_source = rename_root / "redirected-source";
    const auto redirected_dest = rename_root / "redirected-destination";
    create_private_dir(redirected_source);
    create_private_dir(redirected_dest);
    write_text(redirected_source / "payload", "unrelated");
    durable_rename(source_parent / "payload", dest_parent / "payload", [&] {
      fs::rename(source_parent, moved_source_parent);
      fs::rename(dest_parent, moved_dest_parent);
      fs::create_directory_symlink(redirected_source, source_parent);
      fs::create_directory_symlink(redirected_dest, dest_parent);
    });
    expect(!fs::exists(moved_source_parent / "payload") &&
               read_file(moved_dest_parent / "payload", 128) ==
                   Bytes({'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'}),
           "Linux rename did not use original directory descriptors");
    expect(fs::is_empty(redirected_dest) &&
               read_file(redirected_source / "payload", 128) ==
                   Bytes({'u', 'n', 'r', 'e', 'l', 'a', 't', 'e', 'd'}),
           "Linux rename followed swapped parent symlinks");
    rejects(
        [&] {
          durable_rename(source_parent / "payload", dest_parent / "other");
        },
        "Initial parent symlink rejected");
    fs::remove(source_parent);
    fs::remove(dest_parent);
#endif
#ifndef _WIN32
    fs::create_symlink(root / "prefix-test", root / "link-test");
    rejects([&] { (void)read_file(root / "link-test", 128); },
            "No-follow symlink read");
    fs::remove(root / "link-test");
#endif
    Options dry;
    dry.target = target;
    dry.dry_run = true;
    const auto before = snapshot(root);
    expect(run(dry) == 0 && snapshot(root) == before, "Dry-run changed files");
    Options check;
    check.target = target;
    check.check = true;
    expect(run(check) == 3 && snapshot(root) == before, "Check changed files");
    for (const auto &bad_manifest :
         {"{}", "[]", "{\"version\":1}", "{\"version\":\"9.9.9.9\"}"}) {
      auto bad = cdm;
      const std::string value = bad_manifest;
      bad.manifest.assign(value.begin(), value.end());
      rejects([&] { install_cdm(target, bad); }, "Invalid source manifest");
      expect(snapshot(root) == before, "Invalid source changed filesystem");
    }
    auto oversized = cdm;
    oversized.manifest.assign(65537, ' ');
    rejects([&] { install_cdm(target, oversized); },
            "Oversized source manifest");
    expect(snapshot(root) == before, "Oversized source changed filesystem");
    cancelled.store(true);
    rejects([&] { install_cdm(target, cdm); }, "Cancelled before staging");
    cancelled.store(false);
    expect(snapshot(root) == before, "Early cancellation changed filesystem");
    install_cdm(target, cdm);
    expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
           "Install version");
    auto after = snapshot(root);
    expect(run(check) == 0 && snapshot(root) == after,
           "Installed check changed files");
    for (const auto &phase :
         {"prepared", "old_renamed", "old_moved", "new_renamed", "new_moved"}) {
      rejects(
          [&] {
            install_cdm(target, fixture("2.0.0.0"),
                        {{[&](const std::string &current) {
                          if (current == phase) throw Error("Injected failure");
                        }}});
          },
          phase);
      expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
             std::string("Rollback: ") + phase);
      expect(!has_transaction(target), "Pending after rollback");
    }
    for (const auto &phase :
         {"prepared", "old_renamed", "old_moved", "new_renamed", "new_moved"}) {
      bool cancellation_code = false;
      try {
        install_cdm(target, fixture("2.0.0.0"),
                    {{[&](const std::string &current) {
                      if (current == phase) cancelled.store(true);
                    }}});
      } catch (const Error &error) {
        cancellation_code = error.code == Code::cancelled;
      }
      cancelled.store(false);
      expect(cancellation_code,
             std::string("Cancellation exit code at ") + phase);
      expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
             std::string("Cancellation rollback: ") + phase);
      expect(!has_transaction(target), "Pending after cancellation rollback");
    }
#ifdef _WIN32
    {
      const auto library_path = installed_cdm_dir(target) /
                                "_platform_specific" / "win_x64" /
                                binary_name();
      struct LockedFile {
        HANDLE value;
        ~LockedFile() {
          if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
        }
      } locked{CreateFileW(library_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           nullptr)};
      expect(locked.value != INVALID_HANDLE_VALUE, "Open locked DLL fixture");
      rejects([&] { install_cdm(target, fixture("2.0.0.0")); },
              "DLL without delete sharing must block replacement");
      expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
             "Locked DLL installation preserved");
      expect(!has_transaction(target), "Pending after locked DLL rollback");
    }
#endif
    install_cdm(target, fixture("3.0.0.0"));
    restore_cdm(target);
    expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
           "Restore backup");
    restore_cdm(target);
    expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
           "Idempotent restore");
    install_cdm(target, fixture("4.0.0.0"));
    const auto state = root / ".helium-drm-fixer";
    const auto journal_bytes = read_file(state / "journal.json", 1024 * 1024);
    auto journal =
        parse_json(std::string(journal_bytes.begin(), journal_bytes.end()));
    const auto backup = state / ("backup-" + journal["id"].get<std::string>());
#ifdef _WIN32
    const auto backup_dir = backup;
#else
    const auto backup_dir = backup / "1.2.3.4";
#endif
    const auto backup_manifest = read_file(backup_dir / "manifest.json", 65536);
    replace_text(backup_dir / "manifest.json", "{\"version\":\"9.9.9.9\"}");
    const auto tampered = snapshot(root);
    rejects([&] { restore_cdm(target); },
            "Restore must reject modified backup");
    expect(snapshot(root) == tampered,
           "Modified backup recovery changed files");
    replace_text(backup_dir / "manifest.json",
                 std::string(backup_manifest.begin(), backup_manifest.end()));
    journal["id"] = "../../outside";
    replace_text(state / "journal.json", journal.dump());
    const auto malformed_journal = snapshot(root);
    rejects([&] { restore_cdm(target); }, "Journal traversal transaction ID");
    expect(snapshot(root) == malformed_journal,
           "Malformed journal recovery changed files");
    replace_text(state / "journal.json",
                 std::string(journal_bytes.begin(), journal_bytes.end()));
    const auto current_dir = installed_cdm_dir(target);
    fs::remove(current_dir / "manifest.json");
    write_text(current_dir / "manifest.json", "{\"version\":\"9.9.9.9\"}");
    rejects([&] { restore_cdm(target); },
            "Restore must preserve modified current files");
    fs::remove(current_dir / "manifest.json");
    write_file(current_dir / "manifest.json", fixture("4.0.0.0").manifest);
    restore_cdm(target);
    expect(read_cdm(installed_cdm_dir(target)).version == "1.2.3.4",
           "Restore after modification repaired");
    rejects(
        [&] {
          write_text(installed_cdm_dir(target) / "manifest.json", "overwrite");
        },
        "Exclusive write");
    {
      Lock first(root / "test.lock");
      rejects([&] { Lock second(root / "test.lock"); }, "Concurrent lock");
    }
    const auto first_root = root / "first";
    create_private_dir(first_root);
    install_cdm(first_root / "WidevineCdm", cdm);
    restore_cdm(first_root / "WidevineCdm");
    expect(!fs::exists(first_root / "WidevineCdm"),
           "First installation restore should remove new target by rename");
    // Delete only the freshly generated private test directory.
    expect(root.filename().string().starts_with("helium-fixer-test-"),
           "Test cleanup scope");
    fs::remove_all(root);
    std::cout << assertions << " assertions passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "TEST FAILURE: " << error.what() << '\n';
    return 1;
  }
}
