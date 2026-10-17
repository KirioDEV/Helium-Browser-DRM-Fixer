#include "app_update.hpp"

#include <charconv>

namespace fixer {
std::array<std::uint32_t, 3> app_version_parts(const std::string &version) {
  require(!version.empty() && version.size() <= 32, "Invalid app version");
  std::array<std::uint32_t, 3> parts{};
  std::size_t start = 0;
  for (std::size_t index = 0; index < parts.size(); ++index) {
    auto end = version.find('.', start);
    if (end == std::string::npos) end = version.size();
    require(end > start && end - start <= 10 &&
                (end - start == 1 || version[start] != '0'),
            "Invalid app version component");
    for (auto pos = start; pos < end; ++pos)
      require(version[pos] >= '0' && version[pos] <= '9',
              "Invalid app version");
    const auto parsed = std::from_chars(version.data() + start,
                                        version.data() + end, parts[index]);
    require(parsed.ec == std::errc{}, "App version component overflow");
    require(index == 2 ? end == version.size() : end < version.size(),
            "App versions require three components");
    start = end + 1;
  }
  return parts;
}

std::string app_package_name(const std::string &version) {
  (void)app_version_parts(version);
#ifdef _WIN32
  constexpr auto platform = "windows-x64";
#else
  constexpr auto platform = "linux-x86_64-ubuntu24.04";
#endif
  return "helium-drm-fixer-cpp-" + version + "-" + platform + ".zip";
}

AppUpdateStatus parse_app_update(const HttpResponse &response,
                                 const std::string &installed_version) {
  check_cancelled();
  const auto installed = app_version_parts(installed_version);
  AppUpdateStatus result;
  result.installed_version = installed_version;
  require(response.bytes.size() <= 1024 * 1024,
          "App release metadata too large");
  if (response.status == 404) return result;
  require(response.status == 200,
          "App update HTTP status " + std::to_string(response.status),
          Code::failure);
  const auto release =
      parse_json(std::string(response.bytes.begin(), response.bytes.end()));
  try {
    require(release.is_object() && release.at("draft").is_boolean() &&
                !release.at("draft").get<bool>() &&
                release.at("prerelease").is_boolean() &&
                !release.at("prerelease").get<bool>(),
            "App update is not a published stable release");
    const auto tag = release.at("tag_name").get<std::string>();
    const auto version = tag.starts_with('v') ? tag.substr(1) : tag;
    const auto candidate = app_version_parts(version);
    const auto url = "https://github.com/" +
                     std::string(app_update_repository) + "/releases/tag/" +
                     tag;
    require(release.at("html_url") == url,
            "App release belongs to another source");
    result.available_version = version;
    result.release_url = url;
    if (candidate <= installed) {
      result.state = candidate == installed ? AppUpdateState::current
                                            : AppUpdateState::installed_newer;
      result.exit_code = 0;
      return result;
    }
    const auto &assets = release.at("assets");
    require(assets.is_array() && assets.size() <= 64,
            "Invalid app release assets");
    const auto name = app_package_name(version);
    const Json *package = nullptr;
    for (const auto &asset : assets) {
      require(asset.is_object() && asset.at("name").is_string(),
              "Invalid release asset");
      if (asset.at("name") != name) continue;
      require(!package, "Duplicate app update package");
      package = &asset;
    }
    if (!package) {
      result.state = AppUpdateState::no_compatible_package;
      return result;
    }
    const auto download = "https://github.com/" +
                          std::string(app_update_repository) +
                          "/releases/download/" + tag + "/" + name;
    require(package->at("state") == "uploaded" &&
                package->at("browser_download_url") == download &&
                package->at("size").is_number_unsigned() &&
                package->at("size").get<std::uint64_t>() > 0 &&
                package->at("size").get<std::uint64_t>() <= 128 * 1024 * 1024,
            "Invalid app update package metadata");
    result.package_name = name;
    result.state = AppUpdateState::update_available;
    result.exit_code = 0;
  } catch (const Json::exception &) {
    throw Error("Malformed app release metadata");
  }
  check_cancelled();
  return result;
}

AppUpdateStatus check_app_update() {
  return parse_app_update(app_release_request(), FIXER_VERSION);
}

Json app_update_json(const AppUpdateStatus &status) {
  const auto name = [&] {
    switch (status.state) {
      case AppUpdateState::update_available:
        return "update_available";
      case AppUpdateState::current:
        return "current";
      case AppUpdateState::installed_newer:
        return "installed_newer";
      case AppUpdateState::no_public_release:
        return "no_public_release";
      case AppUpdateState::no_compatible_package:
        return "no_compatible_package";
    }
    throw Error("Unknown app update state", Code::invalid);
  }();
  return Json{
      {"schema_version", 1},
      {"state", name},
      {"repository", app_update_repository},
      {"installed_version", status.installed_version},
      {"available_version", status.available_version.empty()
                                ? Json(nullptr)
                                : Json(status.available_version)},
      {"release_url",
       status.release_url.empty() ? Json(nullptr) : Json(status.release_url)},
      {"package_name",
       status.package_name.empty() ? Json(nullptr) : Json(status.package_name)},
      {"exit_code", status.exit_code},
      {"package_verified", false},
      {"self_install_supported", app_self_update_supported()}};
}
}  // namespace fixer
