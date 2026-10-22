#include <csignal>
#include <iostream>

#include "app_update.hpp"
#include "fixer.hpp"
#ifdef _WIN32
// Windows API headers require this include order.
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

int main(int argc, char** argv) {
    std::signal(SIGINT, [](int) { fixer::cancelled.store(true); });
    std::signal(SIGTERM, [](int) { fixer::cancelled.store(true); });
    try {
        std::vector<std::string> arguments;
#ifdef _WIN32
        int count = 0;
        struct Arguments {
            LPWSTR* value;
            ~Arguments() {
                if (value)
                    LocalFree(value);
            }
        } wide{CommandLineToArgvW(GetCommandLineW(), &count)};
        fixer::require(wide.value != nullptr, "Cannot read command line", fixer::Code::failure);
        for (int i = 1; i < count; ++i)
            arguments.push_back(fixer::utf8(fixer::fs::path(wide.value[i])));
        (void)argc;
        (void)argv;
#else
        for (int i = 1; i < argc; ++i)
            arguments.emplace_back(argv[i]);
#endif
        if (arguments.size() == 2 && arguments[0] == "--internal-app-update")
            return fixer::run_app_update_helper(fixer::from_utf8(arguments[1]));
        return fixer::run(fixer::parse_options(arguments));
    } catch (const fixer::Error& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return static_cast<int>(error.code);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
