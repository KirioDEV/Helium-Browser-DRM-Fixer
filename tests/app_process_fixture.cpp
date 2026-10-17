// Test-only trust injection and a parent-exit gate. Neither is in the CLI.
#include <cstdlib>
#include <iostream>

#include "app_update.hpp"
#ifdef _WIN32
// Windows API headers require this include order.
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
    (void)argc;
    (void)argv;
#else
    for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);
#endif
#ifdef _WIN32
    const auto trust_path = _wgetenv(L"FIXER_TEST_APP_TRUST");
    require(trust_path != nullptr, "Missing out-of-band fixture trust");
    const auto key = read_file(fs::path(trust_path), 1024);
#else
    const auto trust_path = std::getenv("FIXER_TEST_APP_TRUST");
    require(trust_path != nullptr, "Missing out-of-band fixture trust");
    const auto key = read_file(from_utf8(trust_path), 1024);
#endif
    if (arguments.size() == 2 && arguments[0] == "--internal-app-update")
      return run_app_update_helper_with_trusted_key(from_utf8(arguments[1]),
                                                    key);
    require(arguments.size() == 1, "Expected fixture config");
    const auto bytes = read_file(from_utf8(arguments[0]), 16384);
    const auto config = parse_json(std::string(bytes.begin(), bytes.end()));
    fs::path job;
    if (config.value("restore", false))
      job =
          start_app_restore(from_utf8(config.at("target").get<std::string>()));
    else
      job = start_app_update_with_trusted_key(
          from_utf8(config.at("directory").get<std::string>()), "1.2.3",
          sha256(read_file(app_executable_path(), file_limit)), key);
    std::cout << Json{{"job", utf8(job)}}.dump() << std::endl;
    if (config.value("hold", false)) {
      std::string line;
      std::getline(std::cin, line);
    }
    return 0;
  } catch (const Error &error) {
    std::cerr << error.what() << '\n';
    return static_cast<int>(error.code);
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
