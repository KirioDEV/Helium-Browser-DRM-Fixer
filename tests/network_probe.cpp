#include <chrono>
#include <iostream>
#include <thread>

#ifdef _WIN32
// Windows API headers require this include order.
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

#include "network_fixture.hpp"

int main(int argc, char** argv) {
    using namespace fixer;
    const auto start = std::chrono::steady_clock::now();
    auto elapsed = [&] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    };
    try {
        require(argc == 2, "Expected a local network fixture configuration", Code::invalid);
#ifdef _WIN32
        int count = 0;
        struct Arguments {
            wchar_t** value;
            ~Arguments() {
                LocalFree(value);
            }
        } arguments{CommandLineToArgvW(GetCommandLineW(), &count)};
        require(arguments.value && count == 2, "Cannot read fixture command line", Code::invalid);
        const auto config_path = fs::path(arguments.value[1]);
        (void)argv;
#else
        const auto config_path = from_utf8(argv[1]);
#endif
        const auto bytes = read_file(config_path, 65536);
        const auto config = parse_json(std::string(bytes.begin(), bytes.end()));
        testing::NetworkSettings settings;
        settings.port = config.at("port").get<unsigned short>();
        settings.ca_file = config.value("ca_file", "");
        settings.peer_sha256 = config.value("peer_sha256", "");
        settings.total_ms = config.value("total_ms", 5000L);
        settings.connect_ms = config.value("connect_ms", 1500L);
        settings.idle_ms = config.value("idle_ms", 1500L);
        settings.low_speed_seconds = config.value("low_speed_seconds", 1L);
        settings.dns_ms = config.value("dns_ms", 1500L);
        settings.dns_delay_ms = config.value("dns_delay_ms", 0L);
        settings.dns_failure = config.value("dns_failure", false);
        settings.system_dns = config.value("system_dns", false);
        settings.app_release = config.value("app_release", false);
        settings.app_asset = config.value("app_asset", false);
        if (config.contains("dns_answers"))
            settings.dns_answers = config.at("dns_answers").get<std::vector<std::vector<std::string>>>();
        const auto cancel_after = config.value("cancel_after_ms", -1L);
        std::jthread canceller;
        if (cancel_after >= 0) {
            canceller = std::jthread([=](std::stop_token stop) {
                const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(cancel_after);
                while (!stop.stop_requested()) {
                    if (std::chrono::steady_clock::now() >= until) {
                        cancelled.store(true);
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
        }
        auto request = [&](const testing::NetworkSettings& options) {
            return testing::network_request(options, config.at("url").get<std::string>(), config.value("body", ""),
                                            config.value("limit", 1024U), config.value("update", false));
        };
        const bool lifecycle = config.value("dns_lifecycle", false);
        if (lifecycle) {
            {
                auto delayed = settings;
                delayed.dns_ms = 100;
                delayed.dns_delay_ms = 800;
                delayed.dns_answers = std::vector<std::vector<std::string>>{{"127.0.0.1"}};
                bool timed_out = false;
                try {
                    (void)request(delayed);
                } catch (const Error& error) {
                    timed_out = error.code == Code::failure && std::string(error.what()) == "DNS lookup timeout";
                }
                require(timed_out, "Fixture DNS worker did not time out");
            }  // The abandoned worker must not reference these destroyed settings.
            bool rejected_pending = false;
            try {
                (void)request(settings);
            } catch (const Error& error) {
                rejected_pending = error.code == Code::failure &&
                                   std::string(error.what()) == "Previous DNS lookup is still pending";
            }
            require(rejected_pending, "Fixture resolver queued a second blocked lookup");
        }
        // Wait for the abandoned worker to finish without assuming an exact thread
        // scheduling delay. Its late, invalid result must not poison a fresh
        // lookup.
        const auto retry_until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        Bytes response;
        for (;;) {
            try {
                response = request(settings);
                break;
            } catch (const Error& error) {
                if (!lifecycle || std::string(error.what()) != "Previous DNS lookup is still pending" ||
                    std::chrono::steady_clock::now() >= retry_until)
                    throw;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        std::cout << Json{{"ok", true}, {"data", hex(response)}, {"elapsed_ms", elapsed()}}.dump() << '\n';
        return 0;
    } catch (const Error& error) {
        std::cout << Json{{"ok", false},
                          {"code", static_cast<int>(error.code)},
                          {"message", error.what()},
                          {"elapsed_ms", elapsed()}}
                             .dump()
                  << '\n';
        return static_cast<int>(error.code);
    } catch (const std::exception& error) {
        std::cout << Json{{"ok", false}, {"code", 1}, {"message", error.what()}, {"elapsed_ms", elapsed()}}.dump()
                  << '\n';
        return 1;
    }
}
