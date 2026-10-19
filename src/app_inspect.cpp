#include "app_identity.hpp"
#include "app_update.hpp"

namespace fixer {
namespace {
template <class Verify>
Json inspect(const fs::path &input, Verify verify) {
  check_cancelled();
  const auto package = fs::absolute(input).lexically_normal();
  const auto name = utf8(package.filename());
  const std::string prefix = std::string(app_update_id) + "-";
#ifdef _WIN32
  const std::string suffix = "-windows-x64.zip";
#else
  const std::string suffix = "-linux-x86_64-ubuntu24.04.zip";
#endif
  require(name.starts_with(prefix) && name.ends_with(suffix) &&
              name.size() > prefix.size() + suffix.size(),
          "Expected a canonical app release ZIP for this platform",
          Code::invalid);
  const auto version =
      name.substr(prefix.size(), name.size() - prefix.size() - suffix.size());
  (void)app_version_parts(version);
  require(name == app_package_name(version), "App release filename mismatch");
  auto manifest_path = package, signature_path = package;
  manifest_path += ".manifest.json";
  signature_path += ".manifest.sig";
  const auto manifest = verify(read_file(manifest_path, 65536),
                               read_file(signature_path, 512), version);
  const auto files =
      unpack_app_package(manifest, read_file(package, 128 * 1024 * 1024));
  Json inventory = Json::object();
  for (const auto &file : files) {
    require(!file.path.starts_with("bin/") || file.executable,
            "Self-update release must not contain external runtime DLLs");
    inventory[file.path] = sha256(file.bytes);
  }
  check_cancelled();
  return {{"schema_version", 1},
          {"state", "verified"},
          {"repository", app_update_repository},
          {"version", version},
          {"platform", manifest.platform},
          {"package_name", name},
          {"package_sha256", manifest.package_sha256},
          {"files", inventory},
          {"package_verified", true},
          {"installation_performed", false}};
}
}  // namespace

Json inspect_app_release(const fs::path &package) {
  require(app_update_key_configured(),
          "App update signing key is not configured");
  return inspect(package, verify_app_manifest);
}

Json inspect_app_release_with_trusted_key(
    const fs::path &package, std::span<const unsigned char> trusted_key) {
  return inspect(package,
                 [&](auto manifest, auto signature, const auto &version) {
                   return verify_app_manifest_with_trusted_key(
                       manifest, signature, trusted_key, version);
                 });
}
}  // namespace fixer
