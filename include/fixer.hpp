#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace fixer {
namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;
using Json = nlohmann::json;
inline constexpr std::size_t package_limit = 64 * 1024 * 1024;
inline constexpr std::size_t file_limit = 64 * 1024 * 1024;
inline constexpr std::size_t expanded_limit = 128 * 1024 * 1024;
inline constexpr char app_id[] = "oimompecagnajdejgnnjijobebaeigek";

enum class Code {
  failure = 1,
  invalid = 2,
  missing = 3,
  security = 4,
  recovery = 5,
  cancelled = 130
};

class Error : public std::runtime_error {
 public:
  Code code;

  explicit Error(std::string message, Code value = Code::failure)
      : std::runtime_error(std::move(message)), code(value) {}
};

inline void require(bool ok, const std::string &message,
                    Code code = Code::security) {
  if (!ok) throw Error(message, code);
}

extern std::atomic_bool cancelled;

void check_cancelled();

std::string platform_name();

std::string binary_name();

std::string lower(std::string value);

std::string utf8(const fs::path &path);

fs::path from_utf8(const std::string &text);

std::array<std::uint32_t, 4> version_parts(const std::string &text);

Json parse_json(const std::string &text);

std::string hex(std::span<const unsigned char> data);

Bytes unhex(const std::string &text);

Bytes read_file(const fs::path &path, std::size_t limit,
                bool prefix_only = false);

void write_file(const fs::path &path, std::span<const unsigned char> data);

void write_text(const fs::path &path, const std::string &text);

void replace_text(const fs::path &path, const std::string &text);

void assert_safe_path(const fs::path &path, bool allow_missing = true);

void create_private_dir(const fs::path &path);

void durable_rename(const fs::path &source, const fs::path &dest,
                    const std::function<void()> &before_rename = {});

void sync_dir(const fs::path &path);

void remove_owned_tree(const fs::path &path, const fs::path &owner);

std::string random_id();

std::string sha256(std::span<const unsigned char> data);

bool verify_signature(std::span<const unsigned char> key,
                      std::span<const unsigned char> signature,
                      std::span<const unsigned char> message, bool rsa);

void ensure_browser_closed();

fs::path cache_path();

fs::path detect_target();

fs::path detect_chrome();

class Lock {
  struct Impl;
  std::unique_ptr<Impl> impl_;

 public:
  explicit Lock(const fs::path &path);

  ~Lock();

  Lock(const Lock &) = delete;

  Lock &operator=(const Lock &) = delete;
};

struct Options {
  bool check = false, dry_run = false, verbose = false, force = false,
       restore = false;
  bool help = false, version = false;
  std::string source = "google";
  fs::path target, chrome, package;
};

Options parse_options(const std::vector<std::string> &arguments);

std::string help_text();

struct Cdm {
  std::string version;
  Bytes manifest;
  Bytes library;
  std::string origin;
  Bytes license;
};

Cdm read_cdm(const fs::path &dir);

void validate_binary(std::span<const unsigned char> bytes, bool library = true);

std::string validate_entry(const std::string &name);

Cdm extract_zip(std::span<const unsigned char> archive);

Cdm verify_crx(std::span<const unsigned char> package,
               const std::string &expected_sha = "");

struct Url {
  std::string host, path;
};

Url validate_url(const std::string &url, bool update = false);

bool public_ipv4(std::span<const unsigned char> address);

bool public_ipv6(std::span<const unsigned char> address);

struct HttpResponse {
  unsigned status = 0;
  Bytes bytes;
  std::string location;
};

using HttpTransport =
    std::function<HttpResponse(const Url &, const std::string &, std::size_t)>;

Bytes request_with_transport(const std::string &url, const std::string &body,
                             std::size_t limit, bool update,
                             const HttpTransport &transport);

Bytes http_request(const std::string &url, const std::string &body,
                   std::size_t limit, bool update = false);

struct Release {
  std::string version, url, checksum;
};

Release parse_release(const std::string &response);

Release latest_release();

Cdm acquire_google(bool force);

struct InstallHooks {
  std::function<void(const std::string &)> phase;
};

void install_cdm(const fs::path &target, const Cdm &cdm,
                 const InstallHooks &hooks = {});

void restore_cdm(const fs::path &target);

fs::path installed_cdm_dir(const fs::path &target);

bool has_transaction(const fs::path &target);

int run(const Options &options);
}  // namespace fixer
