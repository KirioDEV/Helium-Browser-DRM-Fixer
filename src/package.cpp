#include <miniz.h>

#include <algorithm>
#include <set>

#include "directory.hpp"
#include "fixer.hpp"

namespace fixer {
namespace {
std::string text(std::span<const unsigned char> bytes) {
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

std::uint32_t u32(std::span<const unsigned char> data, std::size_t offset) {
  require(offset <= data.size() && data.size() - offset >= 4,
          "Truncated binary header");
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

struct Field {
  unsigned number;
  unsigned wire;
  std::span<const unsigned char> bytes;
};

// A bounded decoder for the three flat messages in Chromium's crx3.proto.
// No crypto is implemented here. Groups, recursive messages and duplicate
// scalar fields are rejected.
std::vector<Field> fields(std::span<const unsigned char> message) {
  std::size_t p = 0;
  auto varint = [&]() {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 10; ++i) {
      require(p < message.size(), "Truncated protobuf varint");
      const auto byte = message[p++];
      require(i != 9 || byte <= 1, "Protobuf varint overflow");
      value |= static_cast<std::uint64_t>(byte & 127) << (i * 7);
      if (!(byte & 128)) return value;
    }
    throw Error("Invalid protobuf varint", Code::security);
  };
  std::vector<Field> out;
  while (p < message.size()) {
    require(out.size() < 64, "Too many protobuf fields");
    const auto tag = varint();
    const auto number = tag >> 3;
    const auto wire = static_cast<unsigned>(tag & 7);
    require(number > 0 && number < (1U << 29), "Invalid protobuf field number");
    std::uint64_t length = 0;
    if (wire == 0) {
      (void)varint();
      out.push_back({static_cast<unsigned>(number), wire, {}});
      continue;
    }
    if (wire == 1)
      length = 8;
    else if (wire == 2)
      length = varint();
    else if (wire == 5)
      length = 4;
    else
      throw Error("Unsupported protobuf wire type", Code::security);
    require(length <= message.size() - p, "Protobuf field exceeds header");
    out.push_back({static_cast<unsigned>(number), wire,
                   message.subspan(p, static_cast<std::size_t>(length))});
    p += static_cast<std::size_t>(length);
  }
  return out;
}

std::string component_id(std::span<const unsigned char> key) {
  auto hash = unhex(sha256(key));
  std::string id;
  for (std::size_t i = 0; i < 16; ++i) {
    id += static_cast<char>('a' + (hash[i] >> 4));
    id += static_cast<char>('a' + (hash[i] & 15));
  }
  return id;
}

void validate_cdm(Cdm &cdm) {
  const auto manifest = parse_json(text(cdm.manifest));
  require(manifest.is_object() && manifest.contains("version") &&
              manifest["version"].is_string(),
          "Invalid CDM manifest");
  cdm.version = manifest["version"].get<std::string>();
  (void)version_parts(cdm.version);
  validate_binary(cdm.library);
}
}  // namespace
void validate_binary(std::span<const unsigned char> bytes, bool library) {
  require(bytes.size() >= 64 && bytes.size() <= file_limit,
          "CDM binary has invalid size");
#ifdef _WIN32
  require(bytes[0] == 'M' && bytes[1] == 'Z', "CDM is not a PE binary");
  const auto offset = static_cast<std::size_t>(u32(bytes, 0x3c));
  require(offset <= bytes.size() && bytes.size() - offset >= 26,
          "Invalid PE header offset");
  require(u32(bytes, offset) == 0x00004550, "Invalid PE signature");
  require(bytes[offset + 4] == 0x64 && bytes[offset + 5] == 0x86,
          "CDM architecture is not x86_64");
  if (library)
    require((bytes[offset + 23] & 0x20) != 0, "PE binary is not a DLL");
  require(bytes[offset + 24] == 0x0b && bytes[offset + 25] == 0x02,
          "CDM is not PE32+");
#else
  require(
      bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F',
      "CDM is not ELF");
  require(bytes[4] == 2 && bytes[5] == 1 && bytes[6] == 1,
          "CDM is not little-endian ELF64");
  require((bytes[16] == 3 || (!library && bytes[16] == 2)) && bytes[17] == 0 &&
              bytes[18] == 62 && bytes[19] == 0,
          "Binary is not the expected x86_64 ELF type");
#endif
}

Cdm read_cdm(const fs::path &dir) { return read_cdm(Directory(dir)); }

Cdm read_cdm(const Directory &directory) {
  Cdm cdm;
  cdm.manifest = directory.read("manifest.json", 65536);
  bool nested = false;
  if (directory.exists("_platform_specific")) {
    const auto specific = directory.child("_platform_specific");
    const auto platform = platform_name() + "_x64";
    if (specific.exists(platform)) {
      const auto binaries = specific.child(platform);
      if (binaries.exists(binary_name())) {
        cdm.library = binaries.read(binary_name(), file_limit);
        nested = true;
      }
    }
  }
  if (!nested) cdm.library = directory.read(binary_name(), file_limit);
  if (directory.exists("LICENSE"))
    cdm.license = directory.read("LICENSE", 1024 * 1024);
  validate_cdm(cdm);
  return cdm;
}

std::string validate_entry(const std::string &name) {
  require(
      !name.empty() && name.size() <= 240 && name[0] != '/' && name[0] != '\\',
      "Invalid archive path");
  require(name.find('\\') == std::string::npos &&
              name.find(':') == std::string::npos,
          "Windows path syntax in archive");
  std::size_t start = 0;
  while (start < name.size()) {
    auto end = name.find('/', start);
    if (end == std::string::npos) end = name.size();
    const auto part = name.substr(start, end - start);
    require(!part.empty() && part != "." && part != ".." &&
                part.back() != '.' && part.back() != ' ',
            "Ambiguous archive path");
    for (char raw : part) {
      const auto c = static_cast<unsigned char>(raw);
      require(c >= 32 && c < 127 && c != '<' && c != '>' && c != '"' &&
                  c != '|' && c != '?' && c != '*',
              "Unsupported archive filename character");
    }
    const auto stem = lower(part.substr(0, part.find('.')));
    require(stem != "con" && stem != "prn" && stem != "aux" && stem != "nul" &&
                !(stem.size() == 4 &&
                  (stem.starts_with("com") || stem.starts_with("lpt")) &&
                  stem[3] >= '0' && stem[3] <= '9'),
            "Windows reserved device name");
    start = end + 1;
  }
  return name.back() == '/' ? name.substr(0, name.size() - 1) : name;
}

Cdm extract_zip(std::span<const unsigned char> archive) {
  require(!archive.empty() && archive.size() <= package_limit,
          "Invalid ZIP size");
  mz_zip_archive zip{};
  require(mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0) != 0,
          "Cannot read ZIP archive");
  struct End {
    mz_zip_archive *zip;
    ~End() { mz_zip_reader_end(zip); }
  } end{&zip};
  require(mz_zip_reader_get_num_files(&zip) <= 256, "Too many archive entries");
  std::set<std::string> names, files;
  std::size_t total = 0;
  Cdm cdm;
  bool manifest_found = false, library_found = false;
  for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&zip); ++i) {
    check_cancelled();
    mz_zip_archive_file_stat stat{};
    require(mz_zip_reader_file_stat(&zip, i, &stat) != 0,
            "Cannot inspect ZIP entry");
    const auto length = mz_zip_reader_get_filename(&zip, i, nullptr, 0);
    require(length > 1 && length <= 241, "Archive filename too long");
    std::string raw(length, '\0');
    require(mz_zip_reader_get_filename(&zip, i, raw.data(), length) == length,
            "Cannot read archive filename");
    raw.resize(length - 1);
    require(raw.find('\0') == std::string::npos,
            "Embedded NUL in archive filename");
    const auto name = validate_entry(raw);
    const auto normalized = lower(name);
    require(names.insert(normalized).second,
            "Duplicate/case-colliding archive entry");
    require(!stat.m_is_encrypted && stat.m_is_supported,
            "Encrypted or unsupported ZIP entry");
    const auto mode = stat.m_external_attr >> 16;
    const auto kind = mode & 0170000;
    require(kind == 0 || kind == 0100000 ||
                (stat.m_is_directory && kind == 0040000),
            "Special/link archive entry rejected");
    require(stat.m_uncomp_size <= file_limit &&
                stat.m_uncomp_size <= expanded_limit - total,
            "ZIP expansion limit exceeded");
    total += static_cast<std::size_t>(stat.m_uncomp_size);
    if (stat.m_is_directory) continue;
    files.insert(normalized);
    // Materialize only the allowlisted CDM files. All entry paths are validated
    // first.
    const bool manifest = name == "manifest.json";
    const bool library = name == binary_name() ||
                         name == "_platform_specific/" + platform_name() +
                                     "_x64/" + binary_name();
    const bool license = name == "LICENSE";
    if (!manifest && !library && !license) continue;
    if (manifest)
      require(stat.m_uncomp_size <= 65536 && !manifest_found,
              "Invalid/duplicate manifest");
    if (license)
      require(stat.m_uncomp_size <= 1024 * 1024, "License exceeds size limit");
    if (library) require(!library_found, "Multiple CDM libraries");
    Bytes bytes(static_cast<std::size_t>(stat.m_uncomp_size));
    require(mz_zip_reader_extract_to_mem(&zip, i, bytes.data(), bytes.size(),
                                         0) != 0,
            "ZIP extraction/CRC check failed");
    if (manifest) {
      cdm.manifest = std::move(bytes);
      manifest_found = true;
    }
    if (library) {
      cdm.library = std::move(bytes);
      library_found = true;
    }
    if (license) cdm.license = std::move(bytes);
  }
  for (const auto &name : names) {
    std::size_t p = name.find('/');
    while (p != std::string::npos) {
      require(!files.contains(name.substr(0, p)),
              "Archive file/directory collision");
      p = name.find('/', p + 1);
    }
  }
  require(manifest_found && library_found, "Required CDM files are missing");
  validate_cdm(cdm);
  return cdm;
}

Cdm verify_crx(std::span<const unsigned char> package,
               const std::string &expected_sha) {
  require(package.size() >= 12 && package.size() <= package_limit,
          "Invalid CRX size");
  if (!expected_sha.empty()) {
    (void)unhex(expected_sha);
    require(sha256(package) == lower(expected_sha), "Package SHA-256 mismatch");
  }
  require(text(package.first(4)) == "Cr24" && u32(package, 4) == 3,
          "Expected a full CRX3 package");
  const auto header_size = static_cast<std::size_t>(u32(package, 8));
  require(header_size > 0 && header_size <= 1024 * 1024 &&
              header_size < package.size() - 12,
          "Invalid CRX header length");
  const auto header = package.subspan(12, header_size);
  for (const auto &marker :
       {Bytes{'P', 'K', 5, 6}, Bytes{'P', 'K', 6, 6}, Bytes{'P', 'K', 6, 7}})
    require(std::search(header.begin(), header.end(), marker.begin(),
                        marker.end()) == header.end(),
            "ZIP end marker inside CRX header");
  struct Proof {
    std::span<const unsigned char> key, signature;
    bool rsa;
  };
  std::vector<Proof> proofs;
  std::span<const unsigned char> signed_data;
  bool signed_seen = false;
  for (const auto &field : fields(header)) {
    if (field.number == 10000) {
      require(field.wire == 2 && !signed_seen,
              "Duplicate/malformed CRX signed data");
      signed_data = field.bytes;
      signed_seen = true;
    } else if (field.number == 2 || field.number == 3) {
      require(field.wire == 2 && proofs.size() < 8,
              "Invalid CRX proof count/type");
      Proof proof{{}, {}, field.number == 2};
      bool key_seen = false, sig_seen = false;
      for (const auto &item : fields(field.bytes)) {
        if (item.number == 1) {
          require(item.wire == 2 && !key_seen, "Malformed proof key");
          proof.key = item.bytes;
          key_seen = true;
        }
        if (item.number == 2) {
          require(item.wire == 2 && !sig_seen, "Malformed proof signature");
          proof.signature = item.bytes;
          sig_seen = true;
        }
      }
      require(!proof.key.empty() && proof.key.size() <= 8192 &&
                  !proof.signature.empty() && proof.signature.size() <= 8192,
              "Missing/oversized CRX proof");
      proofs.push_back(proof);
    }
  }
  require(signed_seen && !proofs.empty(), "CRX signature proof is missing");
  std::span<const unsigned char> id;
  bool id_seen = false;
  for (const auto &field : fields(signed_data))
    if (field.number == 1) {
      require(field.wire == 2 && !id_seen, "Malformed signed CRX ID");
      id = field.bytes;
      id_seen = true;
    }
  require(id.size() == 16, "Invalid signed CRX ID");
  std::string declared;
  for (auto byte : id) {
    declared += static_cast<char>('a' + (byte >> 4));
    declared += static_cast<char>('a' + (byte & 15));
  }
  require(declared == app_id, "Package is not the expected Widevine component");
  static constexpr unsigned char context[] = "CRX3 SignedData";
  Bytes message(std::begin(context),
                std::end(context));  // Includes the required NUL byte.
  const auto size = static_cast<std::uint32_t>(signed_data.size());
  for (unsigned i = 0; i < 4; ++i)
    message.push_back(static_cast<unsigned char>(size >> (8 * i)));
  message.insert(message.end(), signed_data.begin(), signed_data.end());
  const auto zip = package.subspan(12 + header_size);
  message.insert(message.end(), zip.begin(), zip.end());
  bool developer = false;
  for (const auto &proof : proofs) {
    require(verify_signature(proof.key, proof.signature, message, proof.rsa),
            "CRX signature verification failed");
    if (component_id(proof.key) == app_id) developer = true;
  }
  require(developer,
          "A valid signature from the Widevine identity key is required");
  auto cdm = extract_zip(zip);
  cdm.origin = "CRX3 signed by the Widevine component identity key";
  return cdm;
}
}  // namespace fixer
