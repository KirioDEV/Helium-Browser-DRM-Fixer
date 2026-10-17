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

// Offline release inspection with the build-time trust root. Accepts current
// or older versions for release checks, but never installs or executes files.
Json inspect_app_release(const fs::path &package);
Json inspect_app_release_with_trusted_key(
    const fs::path &package, std::span<const unsigned char> trusted_key);

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

// Requires a signature-verified manifest and an existing private staging
// parent. Validates all bytes before creating a new, unique child. The returned
// directory is published by rename only after durable writes and a full
// read-back check. Failures may leave an isolated directory (including .ready
// after a rename sync error). A staging name alone never authorizes
// installation. The caller must revalidate signed metadata/files before any
// future installation.
fs::path stage_app_package(const AppPackageManifest &manifest,
                           std::span<const unsigned char> package,
                           const fs::path &parent);

// Metadata only. No redirects, package download, cache or filesystem writes.
HttpResponse app_release_request_with_transport(const HttpTransport &transport);
HttpResponse app_release_request();
AppUpdateStatus parse_app_update(const HttpResponse &response,
                                 const std::string &installed_version);
AppUpdateStatus check_app_update();
Json app_update_json(const AppUpdateStatus &status);

struct AppUpdateAsset {
  std::string url;
  std::uint64_t size = 0;
};
struct AppUpdateDownload {
  std::string version;
  AppUpdateAsset manifest, signature, package;
};
struct PreparedAppUpdate {
  AppPackageManifest manifest;
  fs::path directory;
  Bytes signed_manifest, signature;
};

struct VerifiedAppUpdate {
  AppPackageManifest manifest;
  // Freshly checked bytes, so replacement need not reopen mutable staged files.
  std::vector<AppPackageFile> files;
};

// Persist exact signature/manifest bytes beside the payload. Requires a freshly
// verified preparation result; this alone never authorizes an app replacement.
void save_prepared_app_update(const PreparedAppUpdate &prepared);
// Read-only cross-process handoff: verifies build-time trust, newer version and
// every staged entry again. Missing/partial metadata is always rejected.
VerifiedAppUpdate read_prepared_app_update(const fs::path &directory,
                                           const std::string &expected_version);
VerifiedAppUpdate read_prepared_app_update_with_trusted_key(
    const fs::path &directory, const std::string &expected_version,
    std::span<const unsigned char> trusted_key);

// Offline executable replacement backend. The caller must first wait for the
// target process to exit. Revalidates the handoff before filesystem writes and
// binds the transaction to an absolute target and the previously observed hash.
// Only standalone packages are supported; documentation remains in staging.
// Keeps durable backup/journal files in a private sibling state directory.
void install_prepared_app_update(const fs::path &directory,
                                 const std::string &expected_version,
                                 const fs::path &target,
                                 const std::string &expected_old_sha256,
                                 const InstallHooks &hooks = {});
void install_prepared_app_update_with_trusted_key(
    const fs::path &directory, const std::string &expected_version,
    const fs::path &target, const std::string &expected_old_sha256,
    std::span<const unsigned char> trusted_key, const InstallHooks &hooks = {});
// Recovery ignores cancellation once started. Unknown/modified files are never
// overwritten or deleted. May also explicitly roll back a committed update.
void restore_app_update(const fs::path &target, const InstallHooks &hooks = {});

// Native current image path, independent of argv[0] and the working directory.
fs::path app_executable_path();
bool app_self_update_supported();
fs::path app_update_jobs(const fs::path &target);
// Launches a private copy of the CURRENT application, never the new payload.
// Returns only after the helper has pinned this process and a durable launch
// decision was recorded. The caller must then exit; success means scheduled,
// not installed.
fs::path start_app_update(const fs::path &directory, const std::string &version,
                          const std::string &expected_self_sha256);
fs::path start_app_update_with_trusted_key(
    const fs::path &directory, const std::string &version,
    const std::string &expected_self_sha256,
    std::span<const unsigned char> trusted_key);
fs::path start_app_restore(const fs::path &target);
// Internal entry point: fixed build-time trust only in the shipped CLI.
int run_app_update_helper(const fs::path &request);
int run_app_update_helper_with_trusted_key(
    const fs::path &request, std::span<const unsigned char> trusted_key);
// Read-only status, including errors from the asynchronous helper.
Json app_update_job_status(const fs::path &job);

AppUpdateDownload parse_app_update_download(
    const HttpResponse &response, const std::string &installed_version);
// Separate from the Google/CDM URL policy. Exactly one redirect to GitHub's
// release-assets host is supported, with the same public-DNS/TLS/peer checks.
Bytes app_asset_request_with_transport(const AppUpdateAsset &asset,
                                       const HttpTransport &transport);
PreparedAppUpdate prepare_app_update_with_transport(
    const AppUpdateDownload &download, const fs::path &parent,
    const HttpTransport &transport);
// Explicit out-of-band trust for release tooling/tests, never downloaded trust.
PreparedAppUpdate prepare_app_update_with_trusted_key(
    const AppUpdateDownload &download, const fs::path &parent,
    const HttpTransport &transport, std::span<const unsigned char> trusted_key);
// Build-time trust only. One shared 120-second network budget covers metadata
// and all three assets. Does not replace or launch the installed application.
PreparedAppUpdate prepare_app_update(const fs::path &parent);
}  // namespace fixer
