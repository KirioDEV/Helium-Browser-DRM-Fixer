#pragma once

#include "fixer.hpp"

namespace fixer {
inline constexpr char app_update_repository[] =
    "KirioDEV/Helium-Browser-DRM-Fixer";
inline constexpr char app_update_api[] =
    "https://api.github.com/repos/KirioDEV/Helium-Browser-DRM-Fixer/releases/"
    "latest";

// Stable application versions have three canonical numeric components.
// Widevine's four-component version parser is deliberately separate.
std::array<std::uint32_t, 3> app_version_parts(const std::string &version);

enum class AppUpdateState {
  update_available,
  current,
  installed_newer,
  no_public_release,
  no_compatible_package
};

struct AppUpdateStatus {
  AppUpdateState state = AppUpdateState::no_public_release;
  std::string installed_version;
  std::string available_version;
  std::string release_url;
  std::string package_name;
  int exit_code = static_cast<int>(Code::missing);
};

std::string app_package_name(const std::string &version);

struct AppPackageManifest {
  std::string version;
  std::string platform;
  std::string package_name;
  std::string package_sha256;
  std::uint64_t package_size = 0;
  Json files;
};

// Signatures cover a domain prefix followed by the exact UTF-8 manifest bytes.
// Explicit trust is for release tooling/tests: never obtain this key from the
// package or metadata being verified. The application uses its build-time key.
AppPackageManifest verify_app_manifest_with_trusted_key(
    std::span<const unsigned char> manifest,
    std::span<const unsigned char> signature,
    std::span<const unsigned char> trusted_key,
    const std::string &expected_version);
AppPackageManifest verify_app_manifest(std::span<const unsigned char> manifest,
                                       std::span<const unsigned char> signature,
                                       const std::string &expected_version);
bool app_update_key_configured();

// Digest verification does not unpack a ZIP or authorize installation.
void verify_app_package_digest(const AppPackageManifest &manifest,
                               std::span<const unsigned char> package);

struct AppPackageFile {
  std::string path;
  Bytes bytes;
  bool executable = false;
};

// Requires a signature-verified manifest. Returns only after every ZIP entry
// matches its signed inventory. Memory only; does not authorize installation.
std::vector<AppPackageFile> unpack_app_package(
    const AppPackageManifest &manifest, std::span<const unsigned char> package);

// Metadata only. No redirects, package download, cache or filesystem writes.
HttpResponse app_release_request_with_transport(const HttpTransport &transport);
HttpResponse app_release_request();
AppUpdateStatus parse_app_update(const HttpResponse &response,
                                 const std::string &installed_version);
AppUpdateStatus check_app_update();
Json app_update_json(const AppUpdateStatus &status);
}  // namespace fixer
