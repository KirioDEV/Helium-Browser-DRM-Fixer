#include <miniz.h>

#include <map>
#include <set>

#include "app_update.hpp"
#include "app_update_trust.hpp"

namespace fixer {
namespace {
using View = std::span<const unsigned char>;

View der(View &input, unsigned char tag) {
  require(input.size() >= 2 && input[0] == tag,
          "Invalid update public key DER");
  std::size_t pos = 2, size = input[1];
  if (size & 0x80) {
    const auto count = size & 0x7f;
    require(
        count > 0 && count <= 2 && input.size() >= 2 + count && input[2] != 0,
        "Noncanonical update public key DER");
    size = 0;
    for (std::size_t i = 0; i < count; ++i) size = size * 256 + input[pos++];
    require(size >= 128, "Noncanonical update public key length");
  }
  require(size <= input.size() - pos, "Truncated update public key");
  const auto value = input.subspan(pos, size);
  input = input.subspan(pos + size);
  return value;
}

std::size_t rsa_signature_size(View key) {
  require(key.size() <= 1024, "Update public key is too large");
  auto sequence = der(key, 0x30);
  require(key.empty(), "Trailing update public key data");
  auto algorithm = der(sequence, 0x30);
  const auto oid = der(algorithm, 0x06);
  const Bytes rsa_oid{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
  require(Bytes(oid.begin(), oid.end()) == rsa_oid &&
              der(algorithm, 5).empty() && algorithm.empty(),
          "Update key must be an RSA encryption public key");
  auto bits = der(sequence, 3);
  require(sequence.empty() && !bits.empty() && bits[0] == 0,
          "Invalid update key bit string");
  bits = bits.subspan(1);
  auto rsa = der(bits, 0x30);
  require(bits.empty(), "Trailing RSA key data");
  const auto modulus = der(rsa, 2), exponent = der(rsa, 2);
  require(rsa.empty() && (modulus.size() == 385 || modulus.size() == 513) &&
              modulus[0] == 0 && (modulus[1] & 0x80) && exponent.size() == 3 &&
              exponent[0] == 1 && exponent[1] == 0 && exponent[2] == 1,
          "Update key requires RSA-3072/4096 and exponent 65537");
  return modulus.size() - 1;
}

std::uint64_t bounded_size(const Json &value, std::uint64_t maximum) {
  require(value.is_number_unsigned() && value.get<std::uint64_t>() <= maximum,
          "Invalid signed update size");
  return value.get<std::uint64_t>();
}

std::string digest(const Json &value) {
  const auto result = value.get<std::string>();
  require(hex(unhex(result)) == result, "Noncanonical update SHA-256");
  return result;
}

AppPackageManifest parse_manifest(View bytes, const std::string &expected) {
  const auto json = parse_json(std::string(bytes.begin(), bytes.end()));
  try {
    require(json.is_object() && json.size() == 7 &&
                json.at("schema_version").is_number_unsigned() &&
                json.at("schema_version") == 1 &&
                json.at("app_id") == "helium-drm-fixer-cpp" &&
                json.at("repository") == app_update_repository,
            "Unknown signed app manifest identity/schema");
    AppPackageManifest result;
    result.version = json.at("version").get<std::string>();
    (void)app_version_parts(result.version);
    require(result.version == expected, "Signed app manifest version mismatch");
#ifdef _WIN32
    constexpr auto platform = "windows-x64";
    const std::string executable = "bin/helium_drm_fixer.exe";
#else
    constexpr auto platform = "linux-x86_64-ubuntu24.04";
    const std::string executable = "bin/helium_drm_fixer";
#endif
    result.platform = json.at("platform").get<std::string>();
    require(result.platform == platform, "Signed update platform mismatch");
    const auto &package = json.at("package");
    require(package.is_object() && package.size() == 3,
            "Invalid signed package entry");
    result.package_name = package.at("name").get<std::string>();
    require(result.package_name == app_package_name(expected),
            "Signed package name mismatch");
    result.package_size = bounded_size(package.at("size"), 128 * 1024 * 1024);
    require(result.package_size > 0, "Signed package is empty");
    result.package_sha256 = digest(package.at("sha256"));
    result.files = json.at("files");
    require(result.files.is_array() && !result.files.empty() &&
                result.files.size() <= 256,
            "Invalid signed file inventory");
    const std::string share = "share/helium-drm-fixer/";
    std::set<std::string> allowed{executable,
                                  share + "README.md",
                                  share + "LICENSE",
                                  share + "SECURITY.md",
                                  share + "THIRD_PARTY.md",
                                  share + "licenses/nlohmann-json-MIT.txt",
                                  share + "licenses/miniz-MIT.txt"};
#ifdef _WIN32
    for (const auto &dll :
         {"libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"})
      allowed.insert("bin/" + std::string(dll));
#endif
    std::set<std::string> files;
    std::uint64_t total = 0;
    for (const auto &file : result.files) {
      require(file.is_object() && file.size() == 4,
              "Invalid signed file entry");
      const auto path = file.at("path").get<std::string>();
      require(validate_entry(path) == path && allowed.contains(path) &&
                  files.insert(lower(path)).second,
              "Unsafe/duplicate signed file path");
      const auto size = bounded_size(file.at("size"), file_limit);
      require(!path.starts_with("bin/") || size >= 64,
              "Signed binary size is too small");
      total += size;
      require(total <= 128 * 1024 * 1024,
              "Signed file inventory exceeds size limit");
      (void)digest(file.at("sha256"));
      require(file.at("executable").is_boolean() &&
                  file.at("executable").get<bool>() == (path == executable),
              "Invalid signed executable flag");
    }
    for (const auto &required :
         {executable, share + "README.md", share + "LICENSE",
          share + "licenses/nlohmann-json-MIT.txt",
          share + "licenses/miniz-MIT.txt"})
      require(files.contains(lower(required)),
              "Signed package lacks binary/license/readme");
#ifdef _WIN32
    const auto runtimes = files.count("bin/libstdc++-6.dll") +
                          files.count("bin/libgcc_s_seh-1.dll") +
                          files.count("bin/libwinpthread-1.dll");
    require(runtimes == 0 || runtimes == 3,
            "Incomplete MinGW runtime inventory");
#endif
    return result;
  } catch (const Json::exception &) {
    throw Error("Malformed signed app manifest");
  }
}
}  // namespace

bool app_update_key_configured() {
  return app_update_trusted_key_hex[0] != '\0';
}

AppPackageManifest verify_app_manifest_with_trusted_key(
    View manifest, View signature, View trusted_key,
    const std::string &expected_version) {
  check_cancelled();
  require(!manifest.empty() && manifest.size() <= 65536,
          "Invalid signed manifest size");
  require(signature.size() == rsa_signature_size(trusted_key),
          "Invalid update signature size");
  constexpr char domain[] = "Helium DRM Fixer app update manifest v1";
  Bytes message(domain, domain + sizeof(domain));
  message.insert(message.end(), manifest.begin(), manifest.end());
  require(verify_signature(trusted_key, signature, message, true),
          "App manifest signature invalid");
  (void)app_version_parts(expected_version);
  auto result = parse_manifest(manifest, expected_version);
  check_cancelled();
  return result;
}

AppPackageManifest verify_app_manifest(View manifest, View signature,
                                       const std::string &expected_version) {
  require(app_update_key_configured(),
          "App update signing key is not configured");
  const std::string encoded(app_update_trusted_key_hex);
  require(encoded.size() % 2 == 0, "Invalid embedded update key");
  Bytes key;
  // unhex() is reserved for fixed-length SHA-256 values.
  for (std::size_t offset = 0; offset < encoded.size(); offset += 2) {
    auto byte = [](char c) -> unsigned char {
      require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
              "Invalid embedded update key");
      return static_cast<unsigned char>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    key.push_back(static_cast<unsigned char>((byte(encoded[offset]) << 4) |
                                             byte(encoded[offset + 1])));
  }
  return verify_app_manifest_with_trusted_key(manifest, signature, key,
                                              expected_version);
}

void verify_app_package_digest(const AppPackageManifest &manifest,
                               View package) {
  check_cancelled();
  require(manifest.package_size > 0 &&
              manifest.package_size <= 128 * 1024 * 1024 &&
              package.size() == manifest.package_size,
          "App package size mismatch");
  require(sha256(package) == manifest.package_sha256,
          "App package SHA-256 mismatch");
  check_cancelled();
}

std::vector<AppPackageFile> unpack_app_package(
    const AppPackageManifest &manifest, View package) {
  verify_app_package_digest(manifest, package);
  require(manifest.files.is_array() && !manifest.files.empty() &&
              manifest.files.size() <= 256,
          "Invalid app inventory");
  mz_zip_archive zip{};
  require(mz_zip_reader_init_mem(&zip, package.data(), package.size(), 0) != 0,
          "Cannot read app ZIP");
  struct End {
    mz_zip_archive *zip;
    ~End() { mz_zip_reader_end(zip); }
  } end{&zip};
  require(mz_zip_reader_get_num_files(&zip) == manifest.files.size(),
          "App ZIP inventory count mismatch");
  std::map<std::string, const Json *> expected;
  for (const auto &file : manifest.files)
    require(expected.emplace(file.at("path").get<std::string>(), &file).second,
            "Duplicate app inventory path");
  std::set<std::string> seen;
  std::vector<AppPackageFile> result;
  std::uint64_t total = 0;
  for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&zip); ++i) {
    check_cancelled();
    mz_zip_archive_file_stat stat{};
    require(mz_zip_reader_file_stat(&zip, i, &stat) != 0,
            "Cannot inspect app ZIP entry");
    const auto length = mz_zip_reader_get_filename(&zip, i, nullptr, 0);
    require(length > 1 && length <= 241, "Invalid app ZIP filename length");
    std::string path(length, '\0');
    require(mz_zip_reader_get_filename(&zip, i, path.data(), length) == length,
            "Cannot read app ZIP filename");
    path.resize(length - 1);
    require(path.find('\0') == std::string::npos &&
                validate_entry(path) == path && seen.insert(lower(path)).second,
            "Unsafe/duplicate app ZIP path");
    const auto found = expected.find(path);
    require(found != expected.end(), "Unlisted app ZIP entry");
    const auto &file = *found->second;
    const bool executable = file.at("executable").get<bool>();
    const auto size = bounded_size(file.at("size"), file_limit);
    const auto mode = stat.m_external_attr >> 16;
    require(!stat.m_is_directory && !stat.m_is_encrypted &&
                stat.m_is_supported &&
                (stat.m_method == 0 || stat.m_method == 8),
            "Unsupported app ZIP entry");
    require(mode == (executable ? 0100755U : 0100644U) &&
                (stat.m_external_attr & 0x10) == 0,
            "Invalid app ZIP file type/permissions");
    require(stat.m_uncomp_size == size && size <= expanded_limit - total,
            "App ZIP expanded size mismatch/limit");
    total += size;
    Bytes bytes(static_cast<std::size_t>(size));
    require(mz_zip_reader_extract_to_mem(&zip, i, bytes.data(), bytes.size(),
                                         0) != 0,
            "App ZIP extraction/CRC check failed");
    require(sha256(bytes) == file.at("sha256").get<std::string>(),
            "App ZIP file SHA-256 mismatch");
    if (path.starts_with("bin/")) {
      validate_binary(bytes, !executable);
#ifdef _WIN32
      if (executable) {
        const auto offset = static_cast<std::size_t>(bytes[0x3c]) |
                            (static_cast<std::size_t>(bytes[0x3d]) << 8) |
                            (static_cast<std::size_t>(bytes[0x3e]) << 16) |
                            (static_cast<std::size_t>(bytes[0x3f]) << 24);
        require((bytes[offset + 23] & 0x20) == 0, "App executable is a DLL");
      }
#endif
    }
    result.push_back({std::move(path), std::move(bytes), executable});
  }
  check_cancelled();
  return result;
}
}  // namespace fixer
