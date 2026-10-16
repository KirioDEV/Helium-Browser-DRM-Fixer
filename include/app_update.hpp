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

// Metadata only. No redirects, package download, cache or filesystem writes.
HttpResponse app_release_request_with_transport(const HttpTransport &transport);
HttpResponse app_release_request();
AppUpdateStatus parse_app_update(const HttpResponse &response,
                                 const std::string &installed_version);
AppUpdateStatus check_app_update();
Json app_update_json(const AppUpdateStatus &status);
}  // namespace fixer
