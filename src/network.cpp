#include <algorithm>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <iostream>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

#include "fixer.hpp"
#ifdef FIXER_NETWORK_TESTING
#include "network_fixture.hpp"
#endif
#ifdef _WIN32
// Winsock types must be available before WinHTTP declarations.
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
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
  // Conservatively exclude IETF special assignments (including transition
  // mechanisms), 6to4 and both documentation prefixes. Public exceptions in
  // 2001::/23 are deliberately not needed for the fixed download hosts.
  if (a[0] == 0x20 && a[1] == 1 && a[2] < 2) return false;
  if (a[0] == 0x20 && a[1] == 2) return false;
  if (a[0] == 0x20 && a[1] == 1 && a[2] == 0x0d && a[3] == 0xb8) return false;
  if (a[0] == 0x3f && a[1] == 0xff && (a[2] & 0xf0) == 0) return false;
  return true;
}

Url validate_url(const std::string &url, bool update) {
  require(url.size() <= 4096 && url.starts_with("https://"),
          "Only HTTPS URLs are allowed");
  for (char raw : url) {
    auto c = static_cast<unsigned char>(raw);
    require(c > 32 && c < 127 && c != '\\', "Invalid URL character");
  }
  const auto end = url.find('/', 8);
  require(end != std::string::npos, "URL must have a path");
  const auto host = lower(url.substr(8, end - 8));
  static const std::set<std::string> download_hosts{"dl.google.com",
                                                    "edgedl.me.gvt1.com"};
  require(update ? (host == "update.googleapis.com" &&
                    url.substr(end) == "/service/update2/json")
                 : download_hosts.contains(host),
          "Unapproved download host or URL authority: " + host);
  require(url.find('#') == std::string::npos, "URL fragments are not allowed");
  return {host, url.substr(end)};
}

namespace {
struct RequestContext {
  std::chrono::steady_clock::time_point deadline;
#ifdef FIXER_NETWORK_TESTING
  const testing::NetworkSettings *fixture = nullptr;
  mutable std::size_t dns_query = 0;
#endif
};

long remaining_ms(const RequestContext &context) {
  check_cancelled();
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          context.deadline - std::chrono::steady_clock::now())
          .count();
  require(remaining > 0, "HTTPS total timeout", Code::failure);
  return static_cast<long>(std::min<decltype(remaining)>(remaining, 120000));
}

unsigned short request_port(const RequestContext &context) {
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture) return context.fixture->port;
#else
  (void)context;
#endif
  return 443;
}

long connect_ms(const RequestContext &context) {
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture)
    return std::min(context.fixture->connect_ms, remaining_ms(context));
#endif
  return std::min(10000L, remaining_ms(context));
}

#ifdef _WIN32
long idle_ms(const RequestContext &context) {
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture)
    return std::min(context.fixture->idle_ms, remaining_ms(context));
#endif
  return std::min(10000L, remaining_ms(context));
}
#endif

struct IpAddress {
  int family;
  std::array<unsigned char, 16> bytes{};

  std::string numeric() const {
    char buffer[INET6_ADDRSTRLEN]{};
    require(inet_ntop(family, bytes.data(), buffer, sizeof(buffer)) != nullptr,
            "Cannot format resolved address", Code::failure);
    return buffer;
  }

  bool operator==(const IpAddress &) const = default;
};

#if !defined(_WIN32) || defined(FIXER_NETWORK_TESTING)
IpAddress parse_address(const std::string &numeric) {
  require(!numeric.empty() && numeric.size() < INET6_ADDRSTRLEN &&
              numeric.find('\0') == std::string::npos,
          "Invalid numeric DNS address");
  IpAddress address{AF_INET};
  if (inet_pton(AF_INET, numeric.c_str(), address.bytes.data()) == 1)
    return address;
  address.family = AF_INET6;
  require(inet_pton(AF_INET6, numeric.c_str(), address.bytes.data()) == 1,
          "Invalid numeric DNS address");
  return address;
}
#endif

IpAddress socket_address(const sockaddr *raw, std::size_t length) {
  require(raw && length >= sizeof(raw->sa_family),
          "Invalid DNS socket address");
  IpAddress address{raw->sa_family};
  const unsigned char *bytes = nullptr;
  std::size_t count = 0;
  if (raw->sa_family == AF_INET) {
    require(length >= sizeof(sockaddr_in), "Truncated IPv4 socket address");
    bytes = reinterpret_cast<const unsigned char *>(
        &reinterpret_cast<const sockaddr_in *>(raw)->sin_addr);
    count = 4;
  } else {
    require(raw->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6),
            "Unsupported/truncated DNS socket address");
    bytes = reinterpret_cast<const unsigned char *>(
        &reinterpret_cast<const sockaddr_in6 *>(raw)->sin6_addr);
    count = 16;
  }
  std::copy_n(bytes, count, address.bytes.begin());
  return address;
}

IpAddress select_public(const std::vector<IpAddress> &addresses) {
  require(!addresses.empty(), "No usable public address", Code::failure);
  require(addresses.size() <= 64, "Too many resolved DNS addresses");
  for (const auto &address : addresses)
    require(address.family == AF_INET
                ? public_ipv4({address.bytes.data(), 4})
                : address.family == AF_INET6 && public_ipv6(address.bytes),
            "Trusted host resolved to a non-public address");
  return addresses.front();
}

IpAddress resolve_public(const std::string &host) {
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
  std::vector<IpAddress> addresses;
  for (auto item = raw; item; item = item->ai_next) {
    require(addresses.size() < 64, "Too many resolved DNS addresses");
    addresses.push_back(socket_address(item->ai_addr, item->ai_addrlen));
  }
  return select_public(addresses);
}

class Resolver {
  struct Task {
    std::function<IpAddress()> resolve;
    std::optional<IpAddress> address;
    std::exception_ptr error;
    std::condition_variable changed;
    bool done = false;
  };
  struct State {
    std::mutex mutex;
    std::condition_variable changed;
    std::shared_ptr<Task> task;
    bool stopping = false;
  };
  std::shared_ptr<State> state_ = std::make_shared<State>();
  std::thread worker_;

 public:
  Resolver()
      : worker_([state = state_] {
          for (;;) {
            std::shared_ptr<Task> task;
            {
              std::unique_lock lock(state->mutex);
              state->changed.wait(
                  lock, [&] { return state->stopping || state->task; });
              if (state->stopping) return;
              task = state->task;
            }
            std::optional<IpAddress> address;
            std::exception_ptr error;
            try {
              address = task->resolve();
            } catch (...) {
              error = std::current_exception();
            }
            {
              std::lock_guard lock(state->mutex);
              task->address = address;
              task->error = error;
              task->done = true;
              state->task.reset();
            }
            task->changed.notify_all();
          }
        }) {}

  ~Resolver() {
    bool pending;
    {
      std::lock_guard lock(state_->mutex);
      state_->stopping = true;
      pending = static_cast<bool>(state_->task);
    }
    state_->changed.notify_all();
    // A system resolver cannot be forcibly interrupted portably. Never join a
    // blocked lookup on process exit. The worker owns its state and each task
    // owns all inputs; neither references this object or a returned request.
    // An idle worker must finish before the runtime tears down its resources.
    if (pending)
      worker_.detach();
    else
      worker_.join();
  }
  Resolver(const Resolver &) = delete;
  Resolver &operator=(const Resolver &) = delete;

  IpAddress lookup(std::function<IpAddress()> resolve,
                   const RequestContext &context) {
    (void)remaining_ms(context);
    long timeout = 10000;
#ifdef FIXER_NETWORK_TESTING
    if (context.fixture) timeout = context.fixture->dns_ms;
#endif
    const auto deadline =
        std::min(context.deadline, std::chrono::steady_clock::now() +
                                       std::chrono::milliseconds(timeout));
    const auto task = std::make_shared<Task>();
    task->resolve = std::move(resolve);
    std::unique_lock lock(state_->mutex);
    require(!state_->task, "Previous DNS lookup is still pending",
            Code::failure);
    state_->task = task;
    state_->changed.notify_one();
    for (;;) {
      lock.unlock();
      (void)remaining_ms(context);
      require(std::chrono::steady_clock::now() < deadline, "DNS lookup timeout",
              Code::failure);
      lock.lock();
      if (task->done) break;
      task->changed.wait_until(
          lock,
          std::min(deadline, std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(20)),
          [&] { return task->done; });
    }
    if (task->error) std::rethrow_exception(task->error);
    require(task->address.has_value(), "DNS result missing", Code::failure);
    return *task->address;
  }
};

IpAddress connection_address(const Url &url, const RequestContext &context) {
  (void)remaining_ms(context);
  std::function<IpAddress()> lookup = [host = url.host] {
    return resolve_public(host);
  };
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture) {
    const auto &settings = *context.fixture;
    std::optional<std::vector<std::string>> answers;
    if (settings.dns_answers) {
      require(context.dns_query < settings.dns_answers->size(),
              "Fixture DNS answer sequence exhausted", Code::failure);
      answers = settings.dns_answers->at(context.dns_query++);
    }
    // Copy every fixture input: the worker may finish after this request and
    // its NetworkSettings have been destroyed.
    lookup = [answers = std::move(answers), failure = settings.dns_failure,
              delay = settings.dns_delay_ms] {
      if (delay) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
      require(!failure, "Cannot resolve trusted host", Code::failure);
      if (answers) {
        require(answers->size() <= 64, "Too many resolved DNS addresses");
        std::vector<IpAddress> addresses;
        for (const auto &answer : *answers)
          addresses.push_back(parse_address(answer));
        (void)select_public(addresses);
      }
      // Only the separate test executable maps validated fixture answers to
      // loopback. Production always connects to the actual selected address.
      return parse_address("127.0.0.1");
    };
  }
#endif
  static Resolver resolver;
  return resolver.lookup(std::move(lookup), context);
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

struct AsyncRequest {
  struct State {
    std::mutex mutex;
    std::condition_variable changed;
    DWORD expected = 0, error = 0, count = 0;
    bool done = false, closed = false;
    std::array<unsigned char, 65536> buffer{};
  } state;
  HINTERNET value;

  static void CALLBACK callback(HINTERNET, DWORD_PTR context, DWORD status,
                                void *information, DWORD size) noexcept {
    if (!context) return;
    auto &current = *reinterpret_cast<State *>(context);
    std::lock_guard guard(current.mutex);
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
      current.closed = true;
    } else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
      current.error =
          information && size >= sizeof(WINHTTP_ASYNC_RESULT)
              ? static_cast<WINHTTP_ASYNC_RESULT *>(information)->dwError
              : ERROR_INVALID_DATA;
      current.done = true;
    } else if (status == current.expected) {
      if (status == WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE) {
        if (information && size == sizeof(DWORD))
          current.count = *static_cast<DWORD *>(information);
        else
          current.error = ERROR_INVALID_DATA;
      } else if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
        current.count = size;
      }
      current.done = true;
    }
    current.changed.notify_all();
  }

  explicit AsyncRequest(HINTERNET handle) : value(handle) {
    require(value != nullptr, "Cannot open HTTPS request", Code::failure);
    DWORD_PTR context = reinterpret_cast<DWORD_PTR>(&state);
    if (!WinHttpSetOption(value, WINHTTP_OPTION_CONTEXT_VALUE, &context,
                          sizeof(context)) ||
        WinHttpSetStatusCallback(value, callback,
                                 WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS |
                                     WINHTTP_CALLBACK_FLAG_HANDLES,
                                 0) == WINHTTP_INVALID_STATUS_CALLBACK) {
      WinHttpCloseHandle(value);
      throw Error("Cannot configure asynchronous HTTPS request", Code::failure);
    }
  }

  ~AsyncRequest() {
    if (WinHttpCloseHandle(value)) {
      // HANDLE_CLOSING is the final callback and cannot overlap another
      // callback for this request. Keep the context and read buffer alive until
      // then.
      std::unique_lock guard(state.mutex);
      state.changed.wait(guard, [&] { return state.closed; });
    }
  }
  AsyncRequest(const AsyncRequest &) = delete;
  AsyncRequest &operator=(const AsyncRequest &) = delete;

  void begin(DWORD expected) {
    std::lock_guard guard(state.mutex);
    state.expected = expected;
    state.error = 0;
    state.count = 0;
    state.done = false;
  }

  DWORD wait(DWORD initiation_error, const RequestContext &context,
             long operation_ms) {
    if (initiation_error != ERROR_SUCCESS &&
        initiation_error != ERROR_IO_PENDING) {
      check_cancelled();
      throw Error("HTTPS operation failed; Windows error " +
                      std::to_string(initiation_error),
                  Code::failure);
    }
    const auto until =
        std::min(context.deadline, std::chrono::steady_clock::now() +
                                       std::chrono::milliseconds(operation_ms));
    std::unique_lock guard(state.mutex);
    while (!state.done) {
      guard.unlock();
      (void)remaining_ms(context);
      require(std::chrono::steady_clock::now() < until,
              "HTTPS operation timeout", Code::failure);
      guard.lock();
      state.changed.wait_for(guard, std::chrono::milliseconds(20),
                             [&] { return state.done; });
    }
    const auto error = state.error, count = state.count;
    guard.unlock();
    (void)remaining_ms(context);
    require(
        error == 0,
        "HTTPS operation failed (TLS, timeout or connection); Windows error " +
            std::to_string(error),
        Code::failure);
    return count;
  }
};

Response request_once(const Url &url, const std::string &body,
                      std::size_t limit, const RequestContext &context) {
  const auto selected = connection_address(url, context);
  Internet session(WinHttpOpen(
      L"Helium-DRM-Fixer/" FIXER_VERSION, WINHTTP_ACCESS_TYPE_NO_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC));
  require(
      WinHttpSetTimeouts(session.value, static_cast<int>(connect_ms(context)),
                         static_cast<int>(connect_ms(context)),
                         static_cast<int>(idle_ms(context)),
                         static_cast<int>(idle_ms(context))) != 0,
      "Cannot set HTTPS timeouts", Code::failure);
  const auto host = from_utf8(url.host).native(),
             path = from_utf8(url.path).native();
  Internet connection(
      WinHttpConnect(session.value, host.c_str(), request_port(context), 0));
  AsyncRequest request(WinHttpOpenRequest(
      connection.value, body.empty() ? L"GET" : L"POST", path.c_str(), nullptr,
      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  auto resolution = from_utf8(selected.numeric()).native();
  require(
      WinHttpSetOption(
          request.value, WINHTTP_OPTION_RESOLUTION_HOSTNAME, resolution.data(),
          static_cast<DWORD>(resolution.size() * sizeof(wchar_t))) != 0,
      "Cannot pin resolved HTTPS address", Code::failure);
  DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  require(WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY,
                           &policy, sizeof(policy)) != 0,
          "Cannot disable automatic redirects", Code::failure);
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture && !context.fixture->peer_sha256.empty()) {
    // Only this separate test target accepts an untrusted fixture CA.
    // Hostname/date checks remain enabled; pin the exact leaf below.
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    require(WinHttpSetOption(request.value, WINHTTP_OPTION_SECURITY_FLAGS,
                             &flags, sizeof(flags)) != 0,
            "Cannot configure fixture certificate pin", Code::failure);
  }
#endif
  auto set_timeouts = [&] {
    require(
        WinHttpSetTimeouts(request.value, static_cast<int>(connect_ms(context)),
                           static_cast<int>(connect_ms(context)),
                           static_cast<int>(idle_ms(context)),
                           static_cast<int>(idle_ms(context))) != 0,
        "Cannot update HTTPS timeouts", Code::failure);
    DWORD receive = static_cast<DWORD>(idle_ms(context));
    DWORD response = static_cast<DWORD>(remaining_ms(context));
    require(WinHttpSetOption(request.value, WINHTTP_OPTION_RECEIVE_TIMEOUT,
                             &receive, sizeof(receive)) != 0 &&
                WinHttpSetOption(request.value,
                                 WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
                                 &response, sizeof(response)) != 0,
            "Cannot update HTTPS response timeouts", Code::failure);
  };
  const wchar_t *headers = body.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
                                        : L"Content-Type: application/json\r\n";
  set_timeouts();
  request.begin(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
  const auto sent = WinHttpSendRequest(
      request.value, headers, body.empty() ? 0 : static_cast<DWORD>(-1L),
      body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char *>(body.data()),
      static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()),
      reinterpret_cast<DWORD_PTR>(&request.state));
  const auto send_error = sent ? ERROR_SUCCESS : GetLastError();
  (void)request.wait(send_error, context, connect_ms(context));
  set_timeouts();
  request.begin(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
  const auto received = WinHttpReceiveResponse(request.value, nullptr);
  const auto receive_error = received ? ERROR_SUCCESS : GetLastError();
  (void)request.wait(receive_error, context, idle_ms(context));
  (void)remaining_ms(context);
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture && !context.fixture->peer_sha256.empty()) {
    PCCERT_CONTEXT raw = nullptr;
    DWORD length = sizeof(raw);
    require(
        WinHttpQueryOption(request.value, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                           &raw, &length) != 0 &&
            raw,
        "Cannot inspect fixture TLS certificate", Code::failure);
    std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>
        certificate(raw, CertFreeCertificateContext);
    require(sha256({raw->pbCertEncoded, raw->cbCertEncoded}) ==
                context.fixture->peer_sha256,
            "Fixture TLS peer certificate pin mismatch");
  }
#endif
  Response response;
  WINHTTP_CONNECTION_INFO connection_info{};
  connection_info.cbSize = sizeof(connection_info);
  DWORD connection_size = sizeof(connection_info);
  require(WinHttpQueryOption(request.value, WINHTTP_OPTION_CONNECTION_INFO,
                             &connection_info, &connection_size) != 0,
          "Cannot inspect connected HTTPS peer", Code::failure);
  const auto &remote = connection_info.RemoteAddress;
  require(socket_address(reinterpret_cast<const sockaddr *>(&remote),
                         sizeof(remote)) == selected,
          "Connected HTTPS peer differs from pinned DNS address");
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture) {
    require(
        remote.ss_family == AF_INET &&
            reinterpret_cast<const sockaddr_in *>(&remote)->sin_addr.s_addr ==
                htonl(INADDR_LOOPBACK),
        "Fixture connection escaped loopback");
  } else
#endif
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
  std::optional<std::uint64_t> expected_length;
  wchar_t length_header[64]{};
  size = sizeof(length_header);
  if (WinHttpQueryHeaders(request.value, WINHTTP_QUERY_CONTENT_LENGTH, nullptr,
                          length_header, &size, nullptr)) {
    const auto length_text = utf8(fs::path(length_header));
    const auto begin = length_text.find_first_not_of(" \t");
    const auto end = length_text.find_last_not_of(" \t");
    require(begin != std::string::npos && end != std::string::npos,
            "Invalid HTTP Content-Length");
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(length_text.data() + begin,
                                        length_text.data() + end + 1, value);
    require(
        parsed.ec == std::errc{} && parsed.ptr == length_text.data() + end + 1,
        "Invalid HTTP Content-Length");
    require(value <= limit, "HTTP response exceeds size limit");
    expected_length = value;
  } else {
    require(GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND,
            "Invalid or oversized HTTP Content-Length");
  }
  for (;;) {
    set_timeouts();
    request.begin(WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE);
    const auto queried = WinHttpQueryDataAvailable(request.value, nullptr);
    const auto query_error = queried ? ERROR_SUCCESS : GetLastError();
    const auto available = request.wait(query_error, context, idle_ms(context));
    if (!available) break;
    request.begin(WINHTTP_CALLBACK_STATUS_READ_COMPLETE);
    const auto reading = WinHttpReadData(
        request.value, request.state.buffer.data(),
        std::min(available, static_cast<DWORD>(request.state.buffer.size())),
        nullptr);
    const auto read_error = reading ? ERROR_SUCCESS : GetLastError();
    const auto count = request.wait(read_error, context, idle_ms(context));
    if (!count) break;
    require(count <= limit - response.bytes.size(),
            "HTTP response exceeds size limit");
    response.bytes.insert(response.bytes.end(), request.state.buffer.begin(),
                          request.state.buffer.begin() + count);
  }
  require(!expected_length || response.bytes.size() == *expected_length,
          "Truncated HTTP response", Code::failure);
  return response;
}
#else
struct Download {
  Response response;
  std::size_t limit;
  bool oversized = false;
};
Response request_once(const Url &url, const std::string &body,
                      std::size_t limit, const RequestContext &context) {
  static const bool initialized =
      curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  require(initialized, "Cannot initialize libcurl", Code::failure);
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(),
                                                             curl_easy_cleanup);
  require(static_cast<bool>(handle), "Cannot create HTTPS client",
          Code::failure);
  Download download{{}, limit, false};
  const auto port = request_port(context);
  const auto full =
      "https://" + url.host + ":" + std::to_string(port) + url.path;
  auto option = [&](CURLoption key, auto value) {
    require(curl_easy_setopt(handle.get(), key, value) == CURLE_OK,
            "Cannot configure HTTPS client", Code::failure);
  };
  option(CURLOPT_URL, full.c_str());
  const auto selected = connection_address(url, context);
  const auto address = selected.family == AF_INET6
                           ? "[" + selected.numeric() + "]"
                           : selected.numeric();
  const auto resolved = url.host + ":" + std::to_string(port) + ":" + address;
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
  option(CURLOPT_CONNECTTIMEOUT_MS, connect_ms(context));
  option(CURLOPT_TIMEOUT_MS, remaining_ms(context));
  option(CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(limit));
  option(CURLOPT_PROXY, "");  // No proxy may bypass the public-address policy.
  option(CURLOPT_LOW_SPEED_LIMIT, 128L);
  option(CURLOPT_LOW_SPEED_TIME, 15L);
#ifdef FIXER_NETWORK_TESTING
  if (context.fixture) {
    if (!context.fixture->ca_file.empty())
      option(CURLOPT_CAINFO, context.fixture->ca_file.c_str());
    option(CURLOPT_LOW_SPEED_TIME, context.fixture->low_speed_seconds);
  }
#endif
  option(CURLOPT_NOSIGNAL, 1L);
  option(CURLOPT_USERAGENT, "Helium-DRM-Fixer/" FIXER_VERSION);
  option(
      CURLOPT_WRITEFUNCTION,
      +[](char *data, std::size_t size, std::size_t count,
          void *userdata) -> std::size_t {
        auto &sink = *static_cast<Download *>(userdata);
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
              sink.response.bytes.end(),
              reinterpret_cast<unsigned char *>(data),
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
          void *userdata) -> std::size_t {
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
              static_cast<Download *>(userdata)->response.location =
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
  require(!download.oversized && result != CURLE_FILESIZE_EXCEEDED,
          "HTTP response exceeds size limit");
  require(result == CURLE_OK,
          std::string("HTTPS request failed: ") + curl_easy_strerror(result),
          Code::failure);
  (void)remaining_ms(context);
  char *connected = nullptr;
  require(curl_easy_getinfo(handle.get(), CURLINFO_PRIMARY_IP, &connected) ==
                  CURLE_OK &&
              connected,
          "Cannot inspect connected HTTPS peer", Code::failure);
  require(parse_address(connected) == selected,
          "Connected HTTPS peer differs from pinned DNS address");
  long status = 0;
  require(curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status) ==
              CURLE_OK,
          "Cannot read HTTP status", Code::failure);
  download.response.status = static_cast<unsigned>(status);
  return download.response;
}
#endif
}  // namespace
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
      (void)validate_url(url);
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
  const RequestContext context{std::chrono::steady_clock::now() +
                               std::chrono::seconds(120)};
  return request_with_transport(
      url, body, limit, update,
      [&](const Url &parsed, const std::string &payload, std::size_t maximum) {
        return request_once(parsed, payload, maximum, context);
      });
}

#ifdef FIXER_NETWORK_TESTING
Bytes testing::network_request(const NetworkSettings &settings,
                               const std::string &url, const std::string &body,
                               std::size_t limit, bool update) {
  require(settings.port && settings.total_ms > 0 &&
              settings.total_ms <= 60000 && settings.connect_ms > 0 &&
              settings.idle_ms > 0 && settings.low_speed_seconds > 0 &&
              settings.dns_ms > 0 && settings.dns_ms <= 60000 &&
              settings.dns_delay_ms >= 0 && settings.dns_delay_ms <= 5000,
          "Invalid network fixture settings");
  const RequestContext context{std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(settings.total_ms),
                               &settings};
  return request_with_transport(
      url, body, limit, update,
      [&](const Url &parsed, const std::string &payload, std::size_t maximum) {
        return request_once(parsed, payload, maximum, context);
      });
}
#endif

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
    for (const auto &candidate : apps)
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
    (void)version_parts(release.version);
    const auto &pipelines = check.at("pipelines");
    require(pipelines.is_array() && pipelines.size() <= 16,
            "Invalid update pipelines");
    // Accept only a complete download -> crx3 pipeline; never install
    // delta/patch output.
    for (const auto &pipeline : pipelines) {
      const auto &operations = pipeline.at("operations");
      if (!operations.is_array() || operations.size() != 2 ||
          operations[0].at("type") != "download" ||
          operations[1].at("type") != "crx3")
        continue;
      const auto &download = operations[0];
      const auto checksum = download.at("out").at("sha256").get<std::string>();
      (void)unhex(checksum);
      require(operations[1].at("in").at("sha256") == checksum,
              "CRX3 input hash does not match download");
      require(download.at("size").is_number_unsigned() &&
                  download.at("size").get<std::uint64_t>() <= package_limit,
              "Invalid/oversized package metadata");
      const auto &urls = download.at("urls");
      require(urls.is_array() && urls.size() <= 16,
              "Invalid download URL list");
      for (const auto &item : urls) {
        const auto url = item.at("url").get<std::string>();
        if (!url.starts_with("https://")) continue;
        (void)validate_url(url);
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
  Json request{{"request",
                {{"@os", ""},
                 {"@updater", ""},
                 {"acceptformat", "crx3,download,puff,run,xz,zucc"},
                 {"apps", Json::array({{{"appid", app_id},
                                        {"installsource", "ondemand"},
                                        {"updatecheck", Json::object()},
                                        {"version", "0.0.0.0"}}})},
                 {"dedup", "cr"},
                 {"ismachine", false},
                 {"arch", "x64"},
                 {"os", {{"arch", "x64"}, {"platform", platform_name()}}},
                 {"protocol", "4.0"},
                 {"updaterversion", "999.0.0.0"}}}};
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
}  // namespace fixer
