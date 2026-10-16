#include "app_update.hpp"

namespace fixer {
AppUpdateDownload parse_app_update_download(
    const HttpResponse &response, const std::string &installed_version) {
  const auto status = parse_app_update(response, installed_version);
  require(status.state == AppUpdateState::update_available,
          "No newer compatible app update is available", Code::missing);
  AppUpdateDownload result;
  result.version = status.available_version;
  const auto tag = status.release_url.substr(status.release_url.rfind('/') + 1);
  const auto prefix = "https://github.com/" +
                      std::string(app_update_repository) +
                      "/releases/download/" + tag + "/";
  const auto release =
      parse_json(std::string(response.bytes.begin(), response.bytes.end()));
  const auto &assets = release.at("assets");
  auto find = [&](const std::string &name, std::uint64_t maximum) {
    const Json *found = nullptr;
    for (const auto &asset : assets) {
      if (asset.at("name") != name) continue;
      require(!found, "Duplicate signed app update asset");
      found = &asset;
    }
    require(found != nullptr, "Signed app update asset missing: " + name,
            Code::missing);
    require(found->at("state") == "uploaded" &&
                found->at("browser_download_url") == prefix + name &&
                found->at("size").is_number_unsigned(),
            "Invalid signed app update asset metadata");
    const auto size = found->at("size").get<std::uint64_t>();
    require(size > 0 && size <= maximum, "Invalid signed app asset size");
    return AppUpdateAsset{prefix + name, size};
  };
  try {
    const auto name = app_package_name(result.version);
    result.manifest = find(name + ".manifest.json", 65536);
    result.signature = find(name + ".manifest.sig", 512);
    require(result.signature.size == 384 || result.signature.size == 512,
            "Invalid app signature asset size");
    result.package = find(name, 128 * 1024 * 1024);
  } catch (const Json::exception &) {
    throw Error("Malformed signed app release assets", Code::security);
  }
  return result;
}

namespace {
using ManifestVerifier = std::function<AppPackageManifest(
    std::span<const unsigned char>, std::span<const unsigned char>)>;

PreparedAppUpdate prepare(const AppUpdateDownload &download,
                          const fs::path &parent,
                          const HttpTransport &transport,
                          const ManifestVerifier &verify) {
  check_cancelled();
  // The DTO is public: bind each URL to the expected version and role again.
  const auto package_name = app_package_name(download.version);
  require(
      app_version_parts(download.version) > app_version_parts(FIXER_VERSION),
      "App preparation requires a newer version", Code::invalid);
  auto check = [&](const AppUpdateAsset &asset, const std::string &suffix) {
    const auto prefix = "https://github.com/" +
                        std::string(app_update_repository) +
                        "/releases/download/";
    const auto plain = prefix + download.version + "/" + package_name + suffix;
    const auto tagged =
        prefix + "v" + download.version + "/" + package_name + suffix;
    require(asset.url == plain || asset.url == tagged,
            "App download version/asset role mismatch");
  };
  check(download.manifest, ".manifest.json");
  check(download.signature, ".manifest.sig");
  check(download.package, "");
  PreparedAppUpdate result;
  result.signed_manifest =
      app_asset_request_with_transport(download.manifest, transport);
  result.signature =
      app_asset_request_with_transport(download.signature, transport);
  result.manifest = verify(result.signed_manifest, result.signature);
  require(result.manifest.package_size == download.package.size,
          "Signed and advertised app package sizes differ");
  const auto package =
      app_asset_request_with_transport(download.package, transport);
  result.directory = stage_app_package(result.manifest, package, parent);
  return result;
}
}  // namespace

PreparedAppUpdate prepare_app_update_with_transport(
    const AppUpdateDownload &download, const fs::path &parent,
    const HttpTransport &transport) {
  require(app_update_key_configured(),
          "App update signing key is not configured");
  return prepare(
      download, parent, transport, [&](auto manifest, auto signature) {
        return verify_app_manifest(manifest, signature, download.version);
      });
}

PreparedAppUpdate prepare_app_update_with_trusted_key(
    const AppUpdateDownload &download, const fs::path &parent,
    const HttpTransport &transport,
    std::span<const unsigned char> trusted_key) {
  require(!trusted_key.empty(), "App update signing key is missing");
  return prepare(download, parent, transport,
                 [&](auto manifest, auto signature) {
                   return verify_app_manifest_with_trusted_key(
                       manifest, signature, trusted_key, download.version);
                 });
}
}  // namespace fixer
