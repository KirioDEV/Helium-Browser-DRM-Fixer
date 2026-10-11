#include <miniz.h>

#include <cstdlib>
#include <iostream>
#include <map>

#include "fixer.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
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
}  // namespace
int main(int argc, char **argv) {
  try {
#ifndef _WIN32
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
      expect(fs::space(parent).available < 1024 * 1024,
             "Low-space test requires a filesystem with less than 1 MiB free");
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
      fs::remove(root);
      std::cout
          << "Real low-space preflight passed without filesystem changes\n";
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
      expect(cancellation_code, "Cancellation exit code");
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
