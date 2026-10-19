#include <miniz.h>

#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>

#include "app_update.hpp"
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

Bytes make_zip(const std::vector<std::pair<std::string, Bytes>> &entries) {
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

void app_update_tests() {
  expect(app_version_parts("1.10.0") > app_version_parts("1.9.9"),
         "App versions were compared lexically");
  for (const auto &version :
       {"", "1.2", "1.2.3.4", "01.2.3", "1.2.03", "v1.2.3", "1.2.3-beta",
        "1.2.3+build", "1.-2.3", "4294967296.0.0", "1.2.3/other"})
    rejects([&] { (void)app_version_parts(version); }, "Invalid app version");
  const auto tag = std::string("v1.10.0");
  const auto release_url = "https://github.com/" +
                           std::string(app_update_repository) +
                           "/releases/tag/" + tag;
  const auto package = app_package_name("1.10.0");
  Json metadata{
      {"tag_name", tag},
      {"draft", false},
      {"prerelease", false},
      {"html_url", release_url},
      {"assets",
       Json::array(
           {Json{{"name", package},
                 {"state", "uploaded"},
                 {"size", 123u},
                 {"browser_download_url",
                  "https://github.com/" + std::string(app_update_repository) +
                      "/releases/download/" + tag + "/" + package}}})}};
  auto response = [](const Json &value) {
    const auto encoded = value.dump();
    return HttpResponse{200, Bytes(encoded.begin(), encoded.end()), {}};
  };
  const auto available = parse_app_update(response(metadata), "1.2.3");
  expect(available.state == AppUpdateState::update_available &&
             available.available_version == "1.10.0" &&
             available.exit_code == 0 && available.package_name == package &&
             available.release_url == release_url,
         "Compatible app update was not detected");
  const auto encoded = app_update_json(available);
  expect(encoded["package_verified"] == false &&
             encoded["self_install_supported"] == app_self_update_supported() &&
             encoded["repository"] == app_update_repository,
         "Metadata check claimed package verification or installation");
  expect(parse_app_update(response(metadata), "1.10.0").state ==
             AppUpdateState::current,
         "Equal app release was offered as update");
  expect(parse_app_update(response(metadata), "2.0.0").state ==
             AppUpdateState::installed_newer,
         "Old app release was offered as downgrade");
  auto no_package = metadata;
  no_package["assets"][0]["name"] = "helium-drm-fixer-old-go.exe";
  const auto incompatible = parse_app_update(response(no_package), "1.0.0");
  expect(incompatible.state == AppUpdateState::no_compatible_package &&
             incompatible.exit_code == 3 && incompatible.package_name.empty(),
         "Go release or wrong platform was offered as C++ update");
  const auto absent = parse_app_update({404, {}, {}}, "1.0.0");
  expect(absent.state == AppUpdateState::no_public_release &&
             absent.exit_code == 3 &&
             app_update_json(absent)["available_version"].is_null(),
         "HTTP 404 was reported as an up-to-date app");
  for (unsigned change = 0; change < 12; ++change) {
    auto bad = metadata;
    if (change == 0) bad["draft"] = true;
    if (change == 1) bad["prerelease"] = true;
    if (change == 2) bad["tag_name"] = "v1.10.0-beta";
    if (change == 3)
      bad["html_url"] = "https://github.com/another/repo/releases/tag/v1.10.0";
    if (change == 4) bad["assets"].push_back(bad["assets"][0]);
    if (change == 5)
      bad["assets"][0]["browser_download_url"] =
          "https://evil.example/update.zip";
    if (change == 6) bad["assets"][0]["size"] = 0;
    if (change == 7) bad["assets"][0]["size"] = -1;
    if (change == 8) bad["assets"][0]["size"] = 128u * 1024 * 1024 + 1;
    if (change == 9) bad["assets"][0]["state"] = "open";
    if (change == 10) bad["draft"] = 0;
    if (change == 11) bad.erase("tag_name");
    rejects([&] { (void)parse_app_update(response(bad), "1.0.0"); },
            "Untrusted/malformed app release metadata");
  }
  int requests = 0;
  const auto fetched = app_release_request_with_transport(
      [&](const Url &url, const std::string &body, std::size_t limit) {
        ++requests;
        expect("https://" + url.host + url.path == app_update_api &&
                   body.empty() && limit == 1024 * 1024,
               "App update request escaped fixed endpoint");
        return response(metadata);
      });
  expect(requests == 1 && fetched.status == 200,
         "App checker made multiple requests");
  for (const auto code : {301u, 302u, 307u, 403u, 429u, 500u})
    rejects(
        [&] {
          (void)app_release_request_with_transport(
              [&](const Url &, const std::string &, std::size_t) {
                return HttpResponse{code, {}, "https://api.github.com/other"};
              });
        },
        "App update followed a redirect or ignored an HTTP error");
  rejects(
      [&] {
        (void)app_release_request_with_transport(
            [](const Url &, const std::string &, std::size_t) {
              return HttpResponse{200, Bytes(1024 * 1024 + 1, 'x'), {}};
            });
      },
      "Unbounded app metadata response");
  rejects([] { (void)validate_url(app_update_api); },
          "GitHub added to CDM policy");
  rejects([] { (void)validate_url(app_update_api, true); },
          "GitHub added to Google policy");
  cancelled.store(true);
  bool stopped = false;
  try {
    (void)app_release_request_with_transport(
        [&](const Url &, const std::string &, std::size_t) {
          ++requests;
          return response(metadata);
        });
  } catch (const Error &error) {
    stopped = error.code == Code::cancelled;
  }
  cancelled.store(false);
  expect(stopped && requests == 1, "Cancelled app checker started a request");
  expect(parse_options({"--check-app-update", "--json"}).check_app_update,
         "App update mode or JSON option missing");
  expect(
      parse_options({"--update-app"}).update_app &&
          parse_options({"--restore-app", "target"}).restore_app == "target" &&
          parse_options({"--app-update-status", "job", "--json"}).json,
      "App update/helper CLI modes missing");
  for (const auto &arguments : std::vector<std::vector<std::string>>{
           {"--restore-app", ""},
           {"--app-update-status", ""},
           {"--update-app", "--check-app-update"},
           {"--update-app", "--restore-app", "target"},
           {"--update-app", "--json"},
           {"--update-app", "--check"},
           {"--restore-app", "target", "--helium-path", "WidevineCdm"}})
    rejects([&] { (void)parse_options(arguments); },
            "Conflicting/empty app operation");
  auto signed_metadata = metadata;
  for (const auto &suffix : {".manifest.json", ".manifest.sig"}) {
    auto asset = metadata["assets"][0];
    asset["name"] = package + suffix;
    asset["browser_download_url"] =
        asset["browser_download_url"].get<std::string>() + suffix;
    asset["size"] = std::string(suffix).ends_with("sig") ? 384u : 100u;
    signed_metadata["assets"].push_back(asset);
  }
  const auto plan =
      parse_app_update_download(response(signed_metadata), "1.0.0");
  expect(plan.version == "1.10.0" && plan.package.size == 123 &&
             plan.signature.size == 384 && plan.manifest.size == 100,
         "Signed app asset plan mismatch");
  rejects([&] { (void)parse_app_update_download(response(metadata), "1.0.0"); },
          "Unsigned app release accepted for download");
  for (unsigned change = 0; change < 8; ++change) {
    auto bad = signed_metadata;
    if (change == 0) bad["assets"].push_back(bad["assets"][1]);
    if (change == 1) bad["assets"][1]["size"] = 65537u;
    if (change == 2) bad["assets"][2]["size"] = 383u;
    if (change == 3) bad["assets"][2]["size"] = -1;
    if (change == 4) bad["assets"][1]["state"] = "open";
    if (change == 5)
      bad["assets"][1]["browser_download_url"] = "https://evil.example/key";
    if (change == 6) bad["assets"][1].erase("size");
    if (change == 7) bad["assets"][1]["size"] = 1.0;
    rejects([&] { (void)parse_app_update_download(response(bad), "1.0.0"); },
            "Invalid signed app asset plan");
  }
  rejects(
      [&] {
        (void)parse_app_update_download(response(signed_metadata), "2.0.0");
      },
      "Download offered a downgrade");
  const AppUpdateAsset asset{plan.package.url, 7};
  const Bytes payload{'f', 'i', 'x', 't', 'u', 'r', 'e'};
  const std::string cdn =
      "https://release-assets.githubusercontent.com/"
      "github-production-release-asset/123/file?token=fixture";
  requests = 0;
  expect(app_asset_request_with_transport(
             asset,
             [&](const Url &url, const std::string &body, std::size_t limit) {
               ++requests;
               expect(body.empty() && limit == (requests == 1 ? 8192u : 7u),
                      "App asset request has wrong body/limit");
               if (requests == 1) {
                 expect("https://" + url.host + url.path == asset.url,
                        "Wrong initial app asset URL");
                 return HttpResponse{302, Bytes(100, 'x'), cdn};
               }
               expect("https://" + url.host + url.path == cdn,
                      "Wrong app CDN URL");
               return HttpResponse{200, payload, {}};
             }) == payload &&
             requests == 2,
         "App CDN redirect failed");
  for (const auto &location :
       {"https://evil.example/file", "http://github.com/file", "/relative",
        "https://release-assets.githubusercontent.com.evil.example/"
        "github-production-release-asset/file",
        "https://release-assets.githubusercontent.com/"
        "github-production-release-asset/file#fragment",
        "https://release-assets.githubusercontent.com/other/file"}) {
    requests = 0;
    rejects(
        [&] {
          (void)app_asset_request_with_transport(
              asset, [&](const Url &, const std::string &, std::size_t) {
                ++requests;
                return HttpResponse{302, {}, location};
              });
        },
        "Unapproved app asset redirect");
    expect(requests == 1, "Unapproved app redirect was requested");
  }
  rejects(
      [&] {
        (void)app_asset_request_with_transport(
            asset, [&](const Url &, const std::string &, std::size_t) {
              return HttpResponse{302, {}, cdn};
            });
      },
      "App redirect loop");
  for (const auto size : {6u, 8u})
    rejects(
        [&] {
          (void)app_asset_request_with_transport(
              asset, [&](const Url &, const std::string &, std::size_t) {
                return HttpResponse{200, Bytes(size), {}};
              });
        },
        "Wrong app response size");
  rejects(
      [&] {
        (void)app_asset_request_with_transport(
            asset, [&](const Url &, const std::string &, std::size_t) {
              return HttpResponse{302, Bytes(8193), cdn};
            });
      },
      "Oversized app redirect body");
  requests = 0;
  rejects(
      [&] {
        (void)app_asset_request_with_transport(
            {"https://evil.example/file", 7},
            [&](const Url &, const std::string &, std::size_t) {
              ++requests;
              return HttpResponse{};
            });
      },
      "Foreign app asset URL");
  expect(requests == 0, "Foreign app asset reached transport");
}

void operation_progress_tests(const fs::path &root) {
  struct Capture {
    std::ostringstream out, err;
    std::streambuf *old_out = std::cout.rdbuf(out.rdbuf());
    std::streambuf *old_err = std::cerr.rdbuf(err.rdbuf());
    ~Capture() {
      std::cout.rdbuf(old_out);
      std::cerr.rdbuf(old_err);
    }
  } capture;
  const auto source = root / "progress-source";
  const auto profile = root / "progress-profile";
  create_private_dir(source);
  create_private_dir(profile);
  const auto replacement = fixture("2.0.0.0");
  write_file(source / "manifest.json", replacement.manifest);
  write_file(source / binary_name(), replacement.library);
  const auto target = profile / "WidevineCdm";
  install_cdm(target, fixture("1.2.3.4"));
  const auto old = snapshot(target);
  Options options;
  options.target = target;
  options.source = "chrome";
  options.chrome = source;
  std::vector<ProgressPhase> phases;
  bool metadata_valid = true;
  const auto result =
      execute_operation(options, [&](const ProgressEvent &event) {
        phases.push_back(event.phase);
        metadata_valid = metadata_valid && event.target == target;
        if (event.phase == ProgressPhase::source_ready)
          metadata_valid =
              metadata_valid && event.version == "2.0.0.0" &&
              event.source.find("not publisher-verified") != std::string::npos;
        if (event.phase == ProgressPhase::completed)
          metadata_valid =
              metadata_valid && !has_transaction(target) &&
              read_cdm(installed_cdm_dir(target)).version == "2.0.0.0";
      });
  const std::vector<ProgressPhase> expected{
      ProgressPhase::target_resolved,
      ProgressPhase::checking_source,
      ProgressPhase::trusting_local_source,
      ProgressPhase::source_ready,
      ProgressPhase::preparing,
      ProgressPhase::preserving_previous,
      ProgressPhase::installing,
      ProgressPhase::verifying_installation,
      ProgressPhase::completed};
  expect(phases == expected && metadata_valid && result.target == target &&
             result.version == "2.0.0.0" && !result.restored,
         "Active core progress order, metadata or completion was incorrect");
  Options restore;
  restore.target = target;
  restore.restore = true;
  phases.clear();
  const auto restored = execute_operation(
      restore,
      [&](const ProgressEvent &event) { phases.push_back(event.phase); });
  expect(
      restored.restored && restored.version.empty() &&
          snapshot(target) == old &&
          phases ==
              std::vector<ProgressPhase>{
                  ProgressPhase::target_resolved, ProgressPhase::restoring,
                  ProgressPhase::restore_validated,
                  ProgressPhase::restore_current_preserved,
                  ProgressPhase::finalizing_restore, ProgressPhase::completed},
      "Structured restore did not preserve the original installation");
  const ProgressObserver broken = [](const ProgressEvent &) {
    throw Error("Presentation failed");
  };
  expect(execute_operation(options, broken).version == "2.0.0.0" &&
             !has_transaction(target),
         "Observer exception interrupted install");
  expect(execute_operation(restore, broken).restored && snapshot(target) == old,
         "Observer exception interrupted restore");
  (void)execute_operation(options, [&](const ProgressEvent &event) {
    if (event.phase == ProgressPhase::completed) cancelled.store(true);
  });
  expect(cancelled.load() && !has_transaction(target) &&
             read_cdm(installed_cdm_dir(target)).version == "2.0.0.0",
         "Late cancellation reclassified a committed installation");
  cancelled.store(false);
  (void)execute_operation(restore, [&](const ProgressEvent &event) {
    if (event.phase == ProgressPhase::restore_validated) cancelled.store(true);
  });
  expect(
      cancelled.load() && snapshot(target) == old && !has_transaction(target),
      "Cancellation interrupted critical restore");
  cancelled.store(false);
  for (const auto cancel_at :
       {ProgressPhase::checking_source, ProgressPhase::source_ready,
        ProgressPhase::preparing, ProgressPhase::preserving_previous,
        ProgressPhase::installing, ProgressPhase::verifying_installation}) {
    bool requested = false, completed = false, correct_code = false;
    try {
      (void)execute_operation(options, [&](const ProgressEvent &event) {
        if (event.phase == cancel_at) {
          requested = true;
          cancelled.store(true);
        }
        if (event.phase == ProgressPhase::completed) completed = true;
      });
    } catch (const Error &error) {
      correct_code = error.code == Code::cancelled;
    }
    cancelled.store(false);
    expect(requested && correct_code && !completed && snapshot(target) == old &&
               !has_transaction(target),
           "Progress cancellation lost original state");
  }
  const auto before = snapshot(root);
  auto bad_package = options;
  bad_package.source = "package";
  bad_package.chrome.clear();
  bad_package.package = source / "manifest.json";
  phases.clear();
  bool invalid_package = false;
  try {
    (void)execute_operation(bad_package, [&](const ProgressEvent &event) {
      phases.push_back(event.phase);
    });
  } catch (const Error &error) {
    invalid_package = error.code == Code::security;
  }
  expect(
      invalid_package && snapshot(root) == before &&
          phases == std::vector<ProgressPhase>{ProgressPhase::target_resolved,
                                               ProgressPhase::checking_source},
      "Rejected source emitted preparation or completion");
  bool queried = false, stopped = false;
  try {
    (void)acquire_google(false, [&](const ProgressEvent &event) {
      queried = event.phase == ProgressPhase::querying_release;
      cancelled.store(true);
    });
  } catch (const Error &error) {
    stopped = error.code == Code::cancelled;
  }
  cancelled.store(false);
  expect(queried && stopped && snapshot(root) == before,
         "Google acquisition did not cancel before querying or caching");
  for (unsigned mode = 0; mode < 5; ++mode) {
    auto bad = options;
    if (mode == 0) bad.check = true;
    if (mode == 1) bad.dry_run = true;
    if (mode == 2) bad.source = "unknown";
    if (mode == 3) bad.force = true;
    if (mode == 4) bad.check_app_update = true;
    bool correct_code = false, emitted = false;
    try {
      (void)execute_operation(bad,
                              [&](const ProgressEvent &) { emitted = true; });
    } catch (const Error &error) {
      correct_code = error.code == Code::invalid;
    }
    expect(correct_code && !emitted && snapshot(root) == before,
           "Active API accepted an invalid or read-only request");
  }
  expect(capture.out.str().empty() && capture.err.str().empty(),
         "Active core wrote directly to the console");
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
  rejects([&] { directory.create_private("child", true); },
          "Exclusive directory creation reused an existing directory");
  rejects([&] { directory.write_text("data", "replacement"); },
          "Exclusive file creation overwrote an existing file");
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

// This deliberately consumes real blocks on a dedicated, bounded test volume.
// Never run it on an ordinary profile or build filesystem.
void fill_test_filesystem(const fs::path &path, std::uintmax_t leave) {
#ifdef _WIN32
  struct File {
    HANDLE value;
    ~File() {
      if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
  } file{CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                         FILE_FLAG_WRITE_THROUGH,
                     nullptr)};
  expect(file.value != INVALID_HANDLE_VALUE,
         "Cannot create disk-space fixture");
  const Bytes block(4096, 'x');
  bool disk_full = false;
  for (std::size_t count = 0; count < 8192; ++count) {
    if (leave && fs::space(path.parent_path()).available <= leave) break;
    DWORD written = 0;
    if (!WriteFile(file.value, block.data(), static_cast<DWORD>(block.size()),
                   &written, nullptr)) {
      const auto error = GetLastError();
      expect(error == ERROR_DISK_FULL || error == ERROR_HANDLE_DISK_FULL,
             "Filler failed for a reason other than disk full");
      disk_full = true;
      break;
    }
    expect(written > 0, "Filler write made no progress");
  }
  expect(leave ? fs::space(path.parent_path()).available <= leave : disk_full,
         "Failed to exhaust bounded test volume");
#else
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
#endif
}

void transaction_space_tests(const fs::path &parent) {
#ifdef _WIN32
  assert_safe_path(parent, false);
  wchar_t volume[MAX_PATH]{}, label[64]{}, filesystem[64]{};
  expect(GetVolumePathNameW(parent.c_str(), volume, MAX_PATH) != 0 &&
             GetVolumeInformationW(volume, label, 64, nullptr, nullptr, nullptr,
                                   filesystem, 64) != 0 &&
             std::wstring(label) == L"FIXER_SPACE_TEST" &&
             std::wstring(filesystem) == L"NTFS" && fs::is_empty(parent),
         "Windows space tests require an empty FIXER_SPACE_TEST NTFS volume");
  const auto space = fs::space(parent);
  expect(
      space.capacity <= 32 * 1024 * 1024 && space.available >= 2 * 1024 * 1024,
      "Windows space tests require a dedicated 2-32 MiB volume");
#else
  struct statfs filesystem{};
  expect(statfs(parent.c_str(), &filesystem) == 0 &&
             filesystem.f_type == TMPFS_MAGIC && fs::is_empty(parent),
         "Transaction space tests require an empty, dedicated tmpfs");
  const auto space = fs::space(parent);
  expect(
      space.capacity <= 16 * 1024 * 1024 && space.available >= 2 * 1024 * 1024,
      "Transaction space tests require a dedicated 2-16 MiB filesystem");
#endif
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
#ifdef _WIN32
        // Small first-install journals can remain resident in NTFS's MFT and
        // legitimately commit even when no data clusters remain. Use an old
        // installation with a larger inventory to force real journal I/O.
        if (!had_old && phase != "staging") continue;
#endif
        std::cout << "Disk-full case: " << (had_old ? "existing" : "empty")
                  << (restoring ? " restore " : " install ") << phase
                  << std::endl;
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
#ifdef _WIN32
        if (had_old)
          for (unsigned index = 0; index < 32; ++index)
            write_text(target / ("preserved-fixture-" + std::to_string(index)),
                       "original extra file");
#endif
        const auto old_files = had_old ? snapshot(target) : Json::object();
        auto replacement = fixture("2.0.0.0");
        replacement.library.resize(256 * 1024);
        if (restoring) install_cdm(target, replacement);
        const auto filler = root / "filler";
        bool injected = false, failed = false;
        Code result = Code::failure;
        const InstallHooks hooks{{[&](const std::string &current) {
          if (current != phase || injected) return;
#ifdef _WIN32
          constexpr auto staging_space = 128 * 1024;
#else
          constexpr auto staging_space = 64 * 1024;
#endif
          fill_test_filesystem(filler, phase == "staging" ? staging_space : 0);
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
#ifdef _WIN32
        // NTFS may reclaim an unlinked file asynchronously after the final
        // handle closes. Wait for the deliberately consumed clusters to return.
        bool reclaimed = false;
        ULARGE_INTEGER available{}, total{}, free{};
        for (unsigned attempt = 0; attempt < 1000; ++attempt) {
          expect(GetDiskFreeSpaceExW(parent.c_str(), &available, &total, &free),
                 "Cannot query test volume after releasing filler");
          if (available.QuadPart <= total.QuadPart &&
              available.QuadPart >= 2 * 1024 * 1024) {
            reclaimed = true;
            break;
          }
          Sleep(10);
        }
        expect(reclaimed, "NTFS did not reclaim the deleted filler in time: " +
                              std::to_string(available.QuadPart) + "/" +
                              std::to_string(total.QuadPart) + "/" +
                              std::to_string(free.QuadPart));
#endif
        const auto state = root / ".helium-drm-fixer";
        if (phase == "staging") {
          expect(!has_transaction(target), "Failed stage published a journal");
          expect(had_old ? snapshot(target) == old_files : !fs::exists(target),
                 "Failed stage changed original installation");
          bool partial_binary = false;
          for (const auto &entry : fs::recursive_directory_iterator(state)) {
            if (entry.path().filename() == binary_name())
              partial_binary =
                  fs::file_size(entry.path()) > 0 &&
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
  std::cout
      << scenarios
      << " real disk-full staging/installation/recovery scenarios passed\n";
}

#ifdef _WIN32
void windows_space_tests(const fs::path &parent) {
  // Run the volume guards before creating even a single fixture file.
  transaction_space_tests(parent);
  const auto root = parent / ("journal-space-" + random_id());
  create_private_dir(root);
  struct Cleanup {
    fs::path root;
    ~Cleanup() {
      std::error_code ignored;
      fs::remove_all(root, ignored);
    }
  } cleanup{root};
  write_text(root / "journal.json", "original journal");
  fill_test_filesystem(root / "filler", 128 * 1024);
  const auto before = snapshot(root);
  bool rejected_preflight = false;
  try {
    install_cdm(root / "WidevineCdm", fixture("1.2.3.4"));
  } catch (const Error &error) {
    rejected_preflight = error.code == Code::failure &&
                         std::string(error.what()) == "Insufficient free space";
  }
  expect(rejected_preflight && snapshot(root) == before,
         "Disk-full preflight changed the test filesystem");
  auto failed_write = [&](const auto &write) {
    bool failed = false;
    try {
      write();
    } catch (const Error &error) {
      failed = error.code == Code::failure &&
               std::string(error.what()) == "Write failed";
    }
    expect(failed, "Expected a real Windows journal write failure");
    expect(snapshot(root) == before,
           "Disk-full journal replacement lost original data or left a "
           "temporary file");
  };
  failed_write([&] {
    replace_text(root / "journal.json", std::string(256 * 1024, 'x'));
  });
  {
    const Directory directory(root);
    failed_write([&] {
      directory.replace("journal.json", std::string(256 * 1024, 'x'));
    });
  }
  std::cout << "13 native Windows disk-full scenarios passed\n";
}
#endif

#ifndef _WIN32
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
    if (argc == 3 && std::string(argv[1]) == "--windows-space") {
      windows_space_tests(fs::absolute(from_utf8(argv[2])));
      return 0;
    }
#endif
    if (argc == 2 && std::string(argv[1]) == "--cache-path") {
      std::cout << utf8(cache_path()) << '\n';
      return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--app-update-trust") {
      std::cout << (app_update_key_configured() ? "configured" : "disabled")
                << '\n';
      return 0;
    }
    if (argc == 4 && std::string(argv[1]) == "--inspect-app-release") {
      std::cout << inspect_app_release_with_trusted_key(
                       from_utf8(argv[2]), read_file(from_utf8(argv[3]), 1024))
                       .dump()
                << '\n';
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--create-private-app-staging") {
      create_private_dir(from_utf8(argv[2]), true);
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--app-transaction-fixture") {
      const auto bytes = read_file(from_utf8(argv[2]), 16384);
      const auto config = parse_json(std::string(bytes.begin(), bytes.end()));
      const auto target = from_utf8(config.at("target").get<std::string>());
      const InstallHooks hooks{{[&](const std::string &phase) {
        if (phase != config.value("phase", "")) return;
        const auto action = config.value("fault", "fail");
        if (action == "crash") std::_Exit(77);
        if (action == "lock") {
          rejects([&] { restore_app_update(target); },
                  "Concurrent app recovery must fail to acquire the lock");
        } else if (action == "cancel") {
          cancelled = true;
        } else if (action == "tamper") {
          if (fs::exists(target)) fs::remove(target);
          write_text(target, "unrelated user file");
        } else {
          throw Error("Injected app transaction failure", Code::failure);
        }
      }}};
#ifdef _WIN32
      struct AppFileLock {
        HANDLE value = INVALID_HANDLE_VALUE;
        ~AppFileLock() {
          if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
        }
      } locked;
      if (config.value("locked_target", false)) {
        locked.value =
            CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        require(locked.value != INVALID_HANDLE_VALUE,
                "Cannot lock synthetic app executable", Code::failure);
      }
#endif
      cancelled = config.value("cancelled", false);
      if (config.value("operation", "install") == "restore") {
        restore_app_update(target, hooks);
      } else {
        const auto directory =
            from_utf8(config.at("directory").get<std::string>());
        const auto version = config.value("version", "1.2.3");
        const auto hash = config.at("old_sha256").get<std::string>();
        if (config.value("compiled_trust", false))
          install_prepared_app_update(directory, version, target, hash, hooks);
        else
          install_prepared_app_update_with_trusted_key(
              directory, version, target, hash,
              read_file(from_utf8(config.at("key").get<std::string>()), 1024),
              hooks);
      }
      return 0;
    }
    if ((argc == 5 && std::string(argv[1]) == "--read-app-handoff") ||
        (argc == 4 &&
         std::string(argv[1]) == "--read-app-handoff-configured")) {
      const auto directory = from_utf8(argv[2]);
      const auto verified =
          argc == 5
              ? read_prepared_app_update_with_trusted_key(
                    directory, argv[4], read_file(from_utf8(argv[3]), 1024))
              : read_prepared_app_update(directory, argv[3]);
      Json files = Json::object();
      for (const auto &file : verified.files)
        files[file.path] = sha256(file.bytes);
      std::cout << Json{{"version", verified.manifest.version},
                        {"files", files}}
                       .dump()
                << '\n';
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--download-app-fixture") {
      const auto configuration = read_file(from_utf8(argv[2]), 65536);
      const auto config =
          parse_json(std::string(configuration.begin(), configuration.end()));
      const auto release = read_file(
          from_utf8(config.at("release").get<std::string>()), 1024 * 1024);
      Json requests = Json::array();
      const HttpTransport transport =
          [&](const Url &url, const std::string &body, std::size_t limit) {
            require(body.empty(), "Unexpected fixture download body");
            const auto full = "https://" + url.host + url.path;
            requests.push_back(full);
            return HttpResponse{
                200,
                read_file(
                    from_utf8(config.at("assets").at(full).get<std::string>()),
                    limit),
                {}};
          };
      try {
        cancelled = config.value("cancelled", false);
        const auto plan = parse_app_update_download(
            {200, release, {}}, config.value("installed", "0.1.0"));
        const auto parent = from_utf8(config.at("parent").get<std::string>());
        const auto result =
            config.value("compiled_trust", false)
                ? prepare_app_update_with_transport(plan, parent, transport)
                : prepare_app_update_with_trusted_key(
                      plan, parent, transport,
                      read_file(from_utf8(config.at("key").get<std::string>()),
                                1024));
        expect(result.signed_manifest ==
                   read_file(from_utf8(config.at("assets")
                                           .at(plan.manifest.url)
                                           .get<std::string>()),
                             65536),
               "Prepared manifest bytes changed");
        std::cout << Json{{"directory", utf8(result.directory)},
                          {"requests", requests}}
                         .dump()
                  << '\n';
      } catch (...) {
        std::cout << Json{{"requests", requests}}.dump() << '\n';
        throw;
      }
      return 0;
    }
    if ((argc == 7 && std::string(argv[1]) == "--verify-app-package") ||
        (argc == 8 &&
         (std::string(argv[1]) == "--stage-app-package" ||
          std::string(argv[1]) == "--stage-app-package-cancelled")) ||
        (argc == 6 &&
         std::string(argv[1]) == "--verify-app-package-configured")) {
      const auto manifest = read_file(from_utf8(argv[2]), 65536);
      const auto signature = read_file(from_utf8(argv[3]), 512);
      const bool explicit_trust = argc != 6;
      const auto version = std::string(argv[explicit_trust ? 6 : 5]);
      const auto parsed =
          explicit_trust ? verify_app_manifest_with_trusted_key(
                               manifest, signature,
                               read_file(from_utf8(argv[4]), 1024), version)
                         : verify_app_manifest(manifest, signature, version);
      const auto package =
          read_file(from_utf8(argv[explicit_trust ? 5 : 4]), 128 * 1024 * 1024);
      if (argc == 8) {
        cancelled = std::string(argv[1]) == "--stage-app-package-cancelled";
        std::cout << utf8(
                         stage_app_package(parsed, package, from_utf8(argv[7])))
                  << '\n';
        return 0;
      }
      const auto files = unpack_app_package(parsed, package);
      std::cout << "Signed manifest and " << files.size()
                << " unpacked app files verified\n";
      return 0;
    }
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
    app_update_tests();
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
    rejects([] { (void)parse_options({"--json"}); },
            "JSON requires inspection");
    rejects([] { (void)parse_options({"--helium-path"}); }, "Missing value");
    rejects([] { (void)parse_options({"--helium-app-path", ""}); },
            "Empty application path");
    rejects([] { (void)parse_options({"--helium-app-path"}); },
            "Missing application path");
    rejects(
        [] {
          (void)parse_options(
              {"--helium-app-path", "app", "--helium-path", "cdm"});
        },
        "Conflicting target paths");
    rejects(
        [] { (void)parse_options({"--helium-app-path", "app", "--restore"}); },
        "Moving application target during restore");
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
    operation_progress_tests(root);
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
    {
      const auto status = inspect_local(check);
      expect(status.state == LocalState::missing && status.exit_code == 3 &&
                 status.target == target && status.version.empty() &&
                 snapshot(root) == before,
             "Structured inspection of a missing CDM changed files");
      cancelled.store(true);
      bool cancelled_status = false;
      try {
        (void)inspect_local(check);
      } catch (const Error &error) {
        cancelled_status = error.code == Code::cancelled;
      }
      cancelled.store(false);
      expect(cancelled_status && snapshot(root) == before,
             "Status inspection swallowed cancellation");
    }
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
    {
      const auto status = inspect_local(check);
      expect(status.state == LocalState::locally_valid &&
                 status.exit_code == 0 && status.version == "1.2.3.4" &&
                 snapshot(root) == after,
             "Structured valid status changed files");
      Options conflicting = check;
      conflicting.helium_app = root;
      const auto unavailable = inspect_local(conflicting);
      expect(unavailable.state == LocalState::unavailable &&
                 unavailable.exit_code == 2 && unavailable.target.empty() &&
                 snapshot(root) == after,
             "Conflicting inspection target was not rejected");
    }
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
  } catch (const Error &error) {
    std::cerr << "TEST FAILURE: " << error.what() << '\n';
    return static_cast<int>(error.code);
  } catch (const std::exception &error) {
    std::cerr << "TEST FAILURE: " << error.what() << '\n';
    return 1;
  }
}
