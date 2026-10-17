#include <map>
#include <set>

#include "app_update.hpp"
#include "directory.hpp"

namespace fixer {
namespace {
constexpr auto manifest_name = "app-update.manifest.json";
constexpr auto signature_name = "app-update.manifest.sig";

Directory open_prepared(const fs::path &path) {
  require(path.is_absolute() && path.lexically_normal() == path,
          "Expected an absolute normalized app staging path");
  const auto name = utf8(path.filename());
  require(name.size() == 49 && name.starts_with("app-update-") &&
              name.ends_with(".ready") &&
              name.substr(11, 32).find_first_not_of("0123456789abcdef") ==
                  std::string::npos,
          "Invalid prepared app directory name");
  const Directory directory(path);
  assert_private_dir(path);
  directory.verify_location();
  return directory;
}

std::vector<AppPackageFile> read_payload(const Directory &directory,
                                         const AppPackageManifest &manifest,
                                         bool metadata) {
  require(manifest.files.is_array() && !manifest.files.empty() &&
              manifest.files.size() <= 256,
          "Invalid app handoff inventory");
  std::map<std::string, const Json *> files;
  std::set<std::string> directories;
  for (const auto &file : manifest.files) {
    const auto path = file.at("path").get<std::string>();
    require(validate_entry(path) == path && files.emplace(path, &file).second,
            "Invalid app handoff path");
    for (auto slash = path.find('/'); slash != std::string::npos;
         slash = path.find('/', slash + 1))
      directories.insert(path.substr(0, slash));
  }
  std::vector<AppPackageFile> result;
  std::size_t total = 0, count = 0;
  std::function<void(const Directory &, const std::string &, unsigned)> visit;
  visit = [&](const Directory &current, const std::string &prefix,
              unsigned depth) {
    require(depth <= 8, "App handoff exceeds directory depth limit");
    for (const auto &entry : current.entries()) {
      check_cancelled();
      require(++count <= 1024, "Too many app handoff entries");
      const auto path = prefix + entry.name;
      if (entry.directory) {
        require(directories.contains(path), "Unlisted app handoff directory");
        visit(current.child(entry.name), path + "/", depth + 1);
        continue;
      }
      if (metadata && (path == manifest_name || path == signature_name))
        continue;
      const auto found = files.find(path);
      require(found != files.end(), "Unlisted app handoff file");
      const auto &file = *found->second;
      const auto size = file.at("size").get<std::uint64_t>();
      require(size <= file_limit && size <= expanded_limit - total,
              "App handoff size limit exceeded");
      auto bytes = current.read(entry.name, static_cast<std::size_t>(size));
      require(bytes.size() == size &&
                  sha256(bytes) == file.at("sha256").get<std::string>(),
              "App handoff file size/hash mismatch");
      total += bytes.size();
      const auto executable = file.at("executable").get<bool>();
      if (path.starts_with("bin/")) {
        validate_binary(bytes, !executable);
#ifdef _WIN32
        if (executable) {
          const auto offset = static_cast<std::size_t>(bytes[0x3c]) |
                              (static_cast<std::size_t>(bytes[0x3d]) << 8) |
                              (static_cast<std::size_t>(bytes[0x3e]) << 16) |
                              (static_cast<std::size_t>(bytes[0x3f]) << 24);
          require((bytes[offset + 23] & 0x20) == 0,
                  "App handoff executable is a DLL");
        }
#endif
      }
      result.push_back({path, std::move(bytes), executable});
      files.erase(found);
    }
  };
  visit(directory, "", 0);
  require(files.empty(), "App handoff file is missing");
  directory.verify_location();
  check_cancelled();
  return result;
}

template <class Verify>
VerifiedAppUpdate read_prepared(const fs::path &path,
                                const std::string &expected, Verify verify) {
  check_cancelled();
  require(app_version_parts(expected) > app_version_parts(FIXER_VERSION),
          "App handoff requires a newer version", Code::invalid);
  const auto directory = open_prepared(path);
  const auto bytes = directory.read(manifest_name, 65536);
  const auto signature = directory.read(signature_name, 512);
  auto manifest = verify(bytes, signature, expected);
  auto files = read_payload(directory, manifest, true);
  return {std::move(manifest), std::move(files)};
}
}  // namespace

void save_prepared_app_update(const PreparedAppUpdate &prepared) {
  check_cancelled();
  require(!prepared.signed_manifest.empty() &&
              prepared.signed_manifest.size() <= 65536 &&
              (prepared.signature.size() == 384 ||
               prepared.signature.size() == 512),
          "Invalid app handoff metadata size");
  const auto directory = open_prepared(prepared.directory);
  (void)read_payload(directory, prepared.manifest, false);
  directory.write(manifest_name, prepared.signed_manifest);
  check_cancelled();
  directory.write(signature_name, prepared.signature);
  require(directory.read(manifest_name, 65536) == prepared.signed_manifest &&
              directory.read(signature_name, 512) == prepared.signature,
          "App handoff metadata read-back mismatch");
  directory.sync();
  directory.verify_location();
}

VerifiedAppUpdate read_prepared_app_update(
    const fs::path &directory, const std::string &expected_version) {
  require(app_update_key_configured(),
          "App update signing key is not configured");
  return read_prepared(directory, expected_version, verify_app_manifest);
}

VerifiedAppUpdate read_prepared_app_update_with_trusted_key(
    const fs::path &directory, const std::string &expected_version,
    std::span<const unsigned char> trusted_key) {
  return read_prepared(directory, expected_version,
                       [&](auto bytes, auto signature, const auto &expected) {
                         return verify_app_manifest_with_trusted_key(
                             bytes, signature, trusted_key, expected);
                       });
}
}  // namespace fixer
