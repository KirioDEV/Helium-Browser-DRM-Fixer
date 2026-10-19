// Test-only out-of-band trust. This executable is never packaged for release.
#include <cstdlib>
#include <iostream>

#include "app_update.hpp"
#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

using namespace fixer;

int main(int argc, char **argv) {
  try {
    std::vector<std::string> arguments;
#ifdef _WIN32
    int count = 0;
    auto wide = CommandLineToArgvW(GetCommandLineW(), &count);
    require(wide != nullptr, "Cannot read fixture arguments");
    for (int i = 1; i < count; ++i)
      arguments.push_back(utf8(fs::path(wide[i])));
    LocalFree(wide);
    const auto trust = _wgetenv(L"FIXER_TEST_APP_TRUST");
#else
    for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);
    const auto trust = std::getenv("FIXER_TEST_APP_TRUST");
#endif
    if (!arguments.empty() && arguments[0] == "--appimage-extract-and-run")
      arguments.erase(arguments.begin());
    if (arguments.empty() ||
        (arguments.size() == 2 && arguments[0] == "--app-update-result")) {
      const auto restarted = std::getenv("FIXER_TEST_GUI_RESTART");
      require(restarted != nullptr, "Missing restart fixture marker");
      write_text(from_utf8(restarted), "restarted");
      return 0;
    }
    require(trust != nullptr, "Missing fixture trust");
    const auto key = read_file(fs::path(trust), 1024);
    if (arguments.size() == 2 && arguments[0] == "--internal-app-update")
      return run_app_update_helper_with_trusted_key(from_utf8(arguments[1]),
                                                    key);
    if (arguments.size() == 2 && arguments[0] == "--inspect") {
      std::cout << inspect_app_release_with_trusted_key(from_utf8(arguments[1]),
                                                        key)
                       .dump();
      return 0;
    }
    if (arguments.size() == 2 && arguments[0] == "--metadata") {
      HttpResponse response;
      response.status = 200;
      response.bytes = read_file(from_utf8(arguments[1]), 1024 * 1024);
      std::cout
          << app_update_json(parse_app_update(response, FIXER_VERSION)).dump();
      return 0;
    }
    require(arguments.size() == 1, "Expected fixture configuration");
    const auto bytes = read_file(from_utf8(arguments[0]), 16384);
    const auto config = parse_json(std::string(bytes.begin(), bytes.end()));
    const auto target = from_utf8(config.at("target").get<std::string>());
    fs::path job;
    if (config.value("restore", false)) {
      job = start_app_restore(target);
    } else {
      const auto package = from_utf8(config.at("package").get<std::string>());
      const auto checked = inspect_app_release_with_trusted_key(package, key);
      const auto version = checked.at("version").get<std::string>();
      auto manifest_path = package, signature_path = package;
      manifest_path += ".manifest.json";
      signature_path += ".manifest.sig";
      const auto manifest = read_file(manifest_path, 65536);
      const auto signature = read_file(signature_path, 512);
      const auto verified = verify_app_manifest_with_trusted_key(
          manifest, signature, key, version);
      const auto parent = app_update_jobs(target) / "packages";
      create_private_dir(parent);
      const auto directory = stage_app_package(
          verified, read_file(package, expanded_limit), parent);
      save_prepared_app_update({verified, directory, manifest, signature});
      job = start_app_update_with_trusted_key(
          directory, version, sha256(read_file(target, file_limit)), key);
    }
    std::cout << Json{{"job", utf8(job)}}.dump() << std::endl;
    if (config.value("hold", false)) {
      std::string line;
      std::getline(std::cin, line);
    }
    return 0;
  } catch (const Error &error) {
    std::cerr << error.what();
    return static_cast<int>(error.code);
  } catch (const std::exception &error) {
    std::cerr << error.what();
    return 1;
  }
}
