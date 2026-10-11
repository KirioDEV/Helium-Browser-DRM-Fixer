#include <csignal>
#include <iostream>

#include "fixer.hpp"
#ifdef _WIN32
// Windows API headers require this include order.
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

int main(int argc, char **argv) {
    std::signal(SIGINT, [](int) { fixer::cancelled.store(true); });
    std::signal(SIGTERM, [](int) { fixer::cancelled.store(true); });
    try {
        std::vector<std::string> arguments;
#ifdef _WIN32
        int count = 0;
        auto wide = CommandLineToArgvW(GetCommandLineW(), &count);
        fixer::require(wide != nullptr, "Cannot read command line",
                       fixer::Code::failure);
        for (int i = 1; i < count; ++i)
            arguments.push_back(fixer::utf8(fixer::fs::path(wide[i])));
        LocalFree(wide);
        (void) argc;
        (void) argv;
#else
        for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);
#endif
        return fixer::run(fixer::parse_options(arguments));
    } catch (const fixer::Error &error) {
        std::cerr << "Error: " << error.what() << '\n';
        return static_cast<int>(error.code);
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
