#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>

#include "fixer.hpp"
#ifdef _WIN32
// Winsock types must be available before WinHTTP declarations.
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <curl/curl.h>
#include <netdb.h>
#endif

namespace fixer {
    bool public_ipv4(std::span<const unsigned char> a) {
        if (a.size() != 4) return false;
        if (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224) return false;
        if (a[0] == 169 && a[1] == 254) return false;
        if (a[0] == 172 && a[1] >= 16 && a[1] <= 31) return false;
        if (a[0] == 192 && (a[1] == 168 || a[1] == 0 || (a[1] == 88 && a[2] == 99)))
            return false;
        if (a[0] == 100 && a[1] >= 64 && a[1] <= 127) return false;
        if (a[0] == 198 && (a[1] == 18 || a[1] == 19 || (a[1] == 51 && a[2] == 100)))
            return false;
        if (a[0] == 203 && a[1] == 0 && a[2] == 113) return false;
        return true;
    }

    bool public_ipv6(std::span<const unsigned char> a) {
        if (a.size() != 16) return false;
        // Global unicast only; reject mapped IPv4, ULA, link-local, multicast and
        // documentation space.
        if ((a[0] & 0xe0) != 0x20) return false;
        if (a[0] == 0x20 && a[1] == 1 && a[2] == 0x0d && a[3] == 0xb8) return false;
        return true;
    }

    Url validate_url(const std::string &url, bool update) {
        require(url.size() <= 4096 && url.starts_with("https://"),
                "Only HTTPS URLs are allowed");
        for (char raw: url) {
            auto c = static_cast<unsigned char>(raw);
            require(c > 32 && c < 127 && c != '\\', "Invalid URL character");
        }
        const auto end = url.find('/', 8);
        require(end != std::string::npos, "URL must have a path");
        const auto host = lower(url.substr(8, end - 8));
        static const std::set<std::string> download_hosts{
            "dl.google.com",
            "edgedl.me.gvt1.com"
        };
        require(update
                    ? (host == "update.googleapis.com" &&
                       url.substr(end) == "/service/update2/json")
                    : download_hosts.contains(host),
                "Unapproved download host or URL authority: " + host);
        require(url.find('#') == std::string::npos, "URL fragments are not allowed");
        return {host, url.substr(end)};
    }

    namespace {
        std::string resolve_public(const std::string &host) {
#ifdef _WIN32
            static const bool initialized = [] {
                WSADATA data{};
                return WSAStartup(MAKEWORD(2, 2), &data) == 0;
            }();
            require(initialized, "Cannot initialize DNS client", Code::failure);
#endif
            addrinfo hints{};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;
            addrinfo *raw = nullptr;
            require(getaddrinfo(host.c_str(), "443", &hints, &raw) == 0,
                    "Cannot resolve trusted host", Code::failure);
            std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> results(raw, freeaddrinfo);
            std::string selected;
            for (auto item = raw; item; item = item->ai_next) {
                const void *address = nullptr;
                std::size_t length = 0;
                if (item->ai_family == AF_INET) {
                    address = &reinterpret_cast<sockaddr_in *>(item->ai_addr)->sin_addr;
                    length = 4;
                    require(public_ipv4({static_cast<const unsigned char *>(address), length}),
                            "Trusted host resolved to a non-public IPv4 address");
                } else if (item->ai_family == AF_INET6) {
                    address = &reinterpret_cast<sockaddr_in6 *>(item->ai_addr)->sin6_addr;
                    length = 16;
                    require(public_ipv6({static_cast<const unsigned char *>(address), length}),
                            "Trusted host resolved to a non-public IPv6 address");
                } else
                    continue;
                char numeric[INET6_ADDRSTRLEN]{};
                require(inet_ntop(item->ai_family, address, numeric, sizeof(numeric)) !=
                        nullptr,
                        "Cannot format resolved address", Code::failure);
                if (selected.empty())
                    selected = item->ai_family == AF_INET6
                                   ? "[" + std::string(numeric) + "]"
                                   : numeric;
            }
            require(!selected.empty(), "No usable public address", Code::failure);
            return selected;
        }

        using Response = HttpResponse;
#ifdef _WIN32
        struct Internet {
            HINTERNET value;

            explicit Internet(HINTERNET h) : value(h) {
                require(h != nullptr, "Cannot open HTTPS handle", Code::failure);
            }

            ~Internet() { WinHttpCloseHandle(value); }
        };

        Response request_once(const Url &url, const std::string &body,
                              std::size_t limit) {
            (void) resolve_public(url.host);
            Internet session(WinHttpOpen(
                L"Helium-DRM-Fixer/" FIXER_VERSION, WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            require(WinHttpSetTimeouts(session.value, 10000, 10000, 10000, 10000) != 0,
                    "Cannot set HTTPS timeouts", Code::failure);
            const auto host = from_utf8(url.host).native(),
                    path = from_utf8(url.path).native();
            Internet connection(WinHttpConnect(session.value, host.c_str(),
                                               INTERNET_DEFAULT_HTTPS_PORT, 0));
            Internet request(WinHttpOpenRequest(
                connection.value, body.empty() ? L"GET" : L"POST", path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
            DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            require(WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY,
                                     &policy, sizeof(policy)) != 0,
                    "Cannot disable automatic redirects", Code::failure);
            const auto start = std::chrono::steady_clock::now();
            const wchar_t *headers = body.empty()
                                         ? WINHTTP_NO_ADDITIONAL_HEADERS
                                         : L"Content-Type: application/json\r\n";
            if (!WinHttpSendRequest(request.value, headers,
                                    body.empty() ? 0 : static_cast<DWORD>(-1L),
                                    body.empty()
                                        ? WINHTTP_NO_REQUEST_DATA
                                        : const_cast<char *>(body.data()),
                                    static_cast<DWORD>(body.size()),
                                    static_cast<DWORD>(body.size()), 0) ||
                !WinHttpReceiveResponse(request.value, nullptr))
                throw Error(
                    "HTTPS request failed (TLS, timeout or connection); Windows error " +
                    std::to_string(GetLastError()),
                    Code::failure);
            Response response;
            WINHTTP_CONNECTION_INFO connection_info{};
            connection_info.cbSize = sizeof(connection_info);
            DWORD connection_size = sizeof(connection_info);
            require(WinHttpQueryOption(request.value, WINHTTP_OPTION_CONNECTION_INFO,
                                       &connection_info, &connection_size) != 0,
                    "Cannot inspect connected HTTPS peer", Code::failure);
            const auto &remote = connection_info.RemoteAddress;
            if (remote.ss_family == AF_INET) {
                auto address = reinterpret_cast<const sockaddr_in *>(&remote);
                require(
                    public_ipv4(
                        {reinterpret_cast<const unsigned char *>(&address->sin_addr), 4}),
                    "Non-public connected HTTPS peer");
            } else if (remote.ss_family == AF_INET6) {
                auto address = reinterpret_cast<const sockaddr_in6 *>(&remote);
                require(
                    public_ipv6(
                        {reinterpret_cast<const unsigned char *>(&address->sin6_addr), 16}),
                    "Non-public connected HTTPS peer");
            } else
                throw Error("Unsupported connected HTTPS address", Code::security);
            DWORD status = 0, size = sizeof(status);
            require(
                WinHttpQueryHeaders(request.value,
                                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    nullptr, &status, &size, nullptr) != 0,
                "Cannot read HTTP status", Code::failure);
            response.status = status;
            if (status >= 300 && status < 400) {
                wchar_t location[4097]{};
                size = sizeof(location);
                require(WinHttpQueryHeaders(request.value, WINHTTP_QUERY_LOCATION, nullptr,
                                            location, &size, nullptr) != 0,
                        "Redirect missing/oversized Location");
                response.location = utf8(fs::path(location));
                return response;
            }
            if (status != 200) return response;
            std::array<unsigned char, 65536> buffer{};
            for (;;) {
                check_cancelled();
                require(
                    std::chrono::steady_clock::now() - start < std::chrono::seconds(120),
                    "HTTPS total timeout", Code::failure);
                DWORD count = 0;
                require(WinHttpReadData(request.value, buffer.data(),
                                        static_cast<DWORD>(buffer.size()), &count) != 0,
                        "HTTPS read failed", Code::failure);
                if (!count) break;
                require(count <= limit - response.bytes.size(),
                        "HTTP response exceeds size limit");
                response.bytes.insert(response.bytes.end(), buffer.begin(),
                                      buffer.begin() + count);
            }
            return response;
        }
#else
        struct Download {
            Response response;
            std::size_t limit;
            bool oversized = false;
        };
        Response request_once(const Url &url, const std::string &body,
                              std::size_t limit) {
            static const bool initialized =
                    curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
            require(initialized, "Cannot initialize libcurl", Code::failure);
            std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(),
                                                                       curl_easy_cleanup);
            require(static_cast<bool>(handle), "Cannot create HTTPS client",
                    Code::failure);
            Download download{{}, limit, false};
            const auto full = "https://" + url.host + url.path;
            auto option = [&](CURLoption key, auto value) {
                require(curl_easy_setopt(handle.get(), key, value) == CURLE_OK,
                        "Cannot configure HTTPS client", Code::failure);
            };
            option(CURLOPT_URL, full.c_str());
            const auto resolved = url.host + ":443:" + resolve_public(url.host);
            std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> addresses(
                curl_slist_append(nullptr, resolved.c_str()), curl_slist_free_all);
            require(static_cast<bool>(addresses), "Cannot pin resolved HTTPS address",
                    Code::failure);
            option(CURLOPT_RESOLVE, addresses.get());
            option(CURLOPT_PROTOCOLS_STR, "https");
            option(CURLOPT_REDIR_PROTOCOLS_STR, "https");
            option(CURLOPT_FOLLOWLOCATION, 0L);
            option(CURLOPT_SSL_VERIFYPEER, 1L);
            option(CURLOPT_SSL_VERIFYHOST, 2L);
            option(CURLOPT_CONNECTTIMEOUT, 10L);
            option(CURLOPT_TIMEOUT, 120L);
            option(CURLOPT_PROXY, ""); // No proxy may bypass the public-address policy.
            option(CURLOPT_LOW_SPEED_LIMIT, 128L);
            option(CURLOPT_LOW_SPEED_TIME, 15L);
            option(CURLOPT_NOSIGNAL, 1L);
            option(CURLOPT_USERAGENT, "Helium-DRM-Fixer/" FIXER_VERSION);
            option(
                CURLOPT_WRITEFUNCTION,
                +[](char *data, std::size_t size, std::size_t count,
                    void *context) -> std::size_t {
                    auto &sink = *static_cast<Download *>(context);
                    if (size && count > SIZE_MAX / size) {
                        sink.oversized = true;
                        return 0;
                    }
                    const auto bytes = size * count;
                    if (bytes > sink.limit - sink.response.bytes.size()) {
                        sink.oversized = true;
                        return 0;
                    }
                    try {
                        sink.response.bytes.insert(
                            sink.response.bytes.end(), reinterpret_cast<unsigned char *>(data),
                            reinterpret_cast<unsigned char *>(data) + bytes);
                    } catch (...) {
                        return 0;
                    }
                    return bytes;
                });
            option(CURLOPT_WRITEDATA, &download);
            option(
                CURLOPT_HEADERFUNCTION,
                +[](char *data, std::size_t size, std::size_t count,
                    void *context) -> std::size_t {
                    if (size && count > SIZE_MAX / size) return 0;
                    const auto bytes = size * count;
                    if (bytes > 8192) return 0;
                    try {
                        std::string line(data, bytes);
                        if (lower(line).starts_with("location:")) {
                            auto value = line.substr(9);
                            auto begin = value.find_first_not_of(" \t");
                            auto end = value.find_last_not_of(" \t\r\n");
                            if (begin != std::string::npos && end != std::string::npos)
                                static_cast<Download *>(context)->response.location =
                                        value.substr(begin, end - begin + 1);
                        }
                    } catch (...) {
                        return 0;
                    }
                    return bytes;
                });
            option(CURLOPT_HEADERDATA, &download);
            option(CURLOPT_NOPROGRESS, 0L);
            option(
                CURLOPT_XFERINFOFUNCTION,
                +[](void *, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
                    return cancelled.load() ? 1 : 0;
                });
            std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
                nullptr, curl_slist_free_all);
            if (!body.empty()) {
                headers.reset(curl_slist_append(nullptr, "Content-Type: application/json"));
                option(CURLOPT_HTTPHEADER, headers.get());
                option(CURLOPT_POSTFIELDS, body.c_str());
                option(CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
            }
            const auto result = curl_easy_perform(handle.get());
            check_cancelled();
            require(!download.oversized, "HTTP response exceeds size limit");
            require(result == CURLE_OK,
                    std::string("HTTPS request failed: ") + curl_easy_strerror(result),
                    Code::failure);
            long status = 0;
            require(curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status) ==
                    CURLE_OK,
                    "Cannot read HTTP status", Code::failure);
            download.response.status = static_cast<unsigned>(status);
            return download.response;
        }
#endif
    } // namespace
    Bytes request_with_transport(const std::string &initial,
                                 const std::string &body, std::size_t limit,
                                 bool update, const HttpTransport &transport) {
        require(limit > 0 && limit <= package_limit, "Invalid HTTP size limit");
        std::string url = initial;
        for (unsigned redirects = 0; redirects <= 3; ++redirects) {
            check_cancelled();
            const auto parsed = validate_url(url, update);
            auto response = transport(parsed, body, limit);
            require(response.bytes.size() <= limit, "HTTP response exceeds size limit");
            if (response.status >= 300 && response.status < 400) {
                require(!update && body.empty() && redirects < 3 &&
                        !response.location.empty(),
                        "Unexpected/excessive HTTP redirect");
                url = response.location.starts_with('/')
                          ? "https://" + parsed.host + response.location
                          : response.location;
                (void) validate_url(url);
                continue;
            }
            require(response.status == 200,
                    "HTTP status " + std::to_string(response.status), Code::failure);
            return response.bytes;
        }
        throw Error("Too many HTTP redirects", Code::security);
    }

    Bytes http_request(const std::string &url, const std::string &body,
                       std::size_t limit, bool update) {
        return request_with_transport(url, body, limit, update, request_once);
    }

    Release parse_release(const std::string &response) {
        auto body = response;
        if (body.starts_with(")]}'")) body.erase(0, 4);
        const auto json = parse_json(body);
        try {
            require(json.at("response").at("protocol") == "4.0",
                    "Unsupported update protocol");
            const auto &apps = json.at("response").at("apps");
            require(apps.is_array() && apps.size() <= 32, "Invalid update app list");
            const Json *app = nullptr;
            for (const auto &candidate: apps)
                if (candidate.at("appid") == app_id) {
                    require(!app, "Duplicate update app identity");
                    app = &candidate;
                }
            require(app && app->at("status") == "ok",
                    "Widevine update metadata missing/non-ok");
            const auto &check = app->at("updatecheck");
            require(check.at("status") == "ok", "No usable Widevine update available",
                    Code::failure);
            Release release{check.at("nextversion").get<std::string>(), {}, {}};
            (void) version_parts(release.version);
            const auto &pipelines = check.at("pipelines");
            require(pipelines.is_array() && pipelines.size() <= 16,
                    "Invalid update pipelines");
            // Accept only a complete download -> crx3 pipeline; never install
            // delta/patch output.
            for (const auto &pipeline: pipelines) {
                const auto &operations = pipeline.at("operations");
                if (!operations.is_array() || operations.size() != 2 ||
                    operations[0].at("type") != "download" ||
                    operations[1].at("type") != "crx3")
                    continue;
                const auto &download = operations[0];
                const auto checksum = download.at("out").at("sha256").get<std::string>();
                (void) unhex(checksum);
                require(operations[1].at("in").at("sha256") == checksum,
                        "CRX3 input hash does not match download");
                require(download.at("size").is_number_unsigned() &&
                        download.at("size").get<std::uint64_t>() <= package_limit,
                        "Invalid/oversized package metadata");
                const auto &urls = download.at("urls");
                require(urls.is_array() && urls.size() <= 16,
                        "Invalid download URL list");
                for (const auto &item: urls) {
                    const auto url = item.at("url").get<std::string>();
                    if (!url.starts_with("https://")) continue;
                    (void) validate_url(url);
                    release.url = url;
                    release.checksum = lower(checksum);
                    return release;
                }
            }
            throw Error("No full CRX3 download with trusted HTTPS URL and SHA-256",
                        Code::security);
        } catch (const Json::exception &) {
            throw Error("Unsupported/malformed Google update response", Code::security);
        }
    }

    Release latest_release() {
        // Google's current service rejects reduced acceptformat lists. The response
        // parser still accepts only full download -> crx3 pipelines, never run/patch.
        Json request{
            {
                "request",
                {
                    {"@os", ""},
                    {"@updater", ""},
                    {"acceptformat", "crx3,download,puff,run,xz,zucc"},
                    {
                        "apps", Json::array({
                            {
                                {"appid", app_id},
                                {"installsource", "ondemand"},
                                {"updatecheck", Json::object()},
                                {"version", "0.0.0.0"}
                            }
                        })
                    },
                    {"dedup", "cr"},
                    {"ismachine", false},
                    {"arch", "x64"},
                    {"os", {{"arch", "x64"}, {"platform", platform_name()}}},
                    {"protocol", "4.0"},
                    {"updaterversion", "999.0.0.0"}
                }
            }
        };
        auto bytes =
                http_request("https://update.googleapis.com/service/update2/json",
                             request.dump(), 1024 * 1024, true);
        return parse_release(
            {reinterpret_cast<const char *>(bytes.data()), bytes.size()});
    }

    Cdm acquire_google(bool force) {
        std::cout << "Querying Google for Widevine...\n";
        const auto release = latest_release();
        auto cache = cache_path();
        create_private_dir(cache);
        Lock lock(cache / "cache.lock");
        const auto path =
                cache / (platform_name() + "-x64-" + release.checksum + ".crx3");
        Bytes bytes;
        if (!force && fs::exists(path)) {
            std::cout << "Rechecking cached package...\n";
            bytes = read_file(path, package_limit);
        } else {
            std::cout << "Downloading and verifying Widevine " << release.version
                    << "...\n";
            bytes = http_request(release.url, "", package_limit);
        }
        auto cdm = verify_crx(bytes, release.checksum);
        require(cdm.version == release.version,
                "Signed manifest version does not match update metadata");
        if (force || !fs::exists(path)) {
            const auto temp = cache / ("package-" + random_id() + ".tmp");
            write_file(temp, bytes);
            try {
                if (fs::exists(path)) {
                    assert_safe_path(path, false);
                    fs::remove(path);
                }
                durable_rename(temp, path);
            } catch (...) {
                fs::remove(temp);
                throw;
            }
        }
        return cdm;
    }
} // namespace fixer
