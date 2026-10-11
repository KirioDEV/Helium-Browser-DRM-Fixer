#include <algorithm>
#include <charconv>
#include <iostream>
#include <set>

#include "fixer.hpp"

namespace fixer {
std::atomic_bool cancelled{false};
static_assert(std::atomic_bool::is_always_lock_free,
              "Signal cancellation requires lock-free atomics");
void check_cancelled() {
  if (cancelled.load()) throw Error("Operation cancelled", Code::cancelled);
}
std::string lower(std::string value) {
  for (char& c : value)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
  return value;
}
std::string utf8(const fs::path& path) {
  const auto value = path.u8string();
  return {reinterpret_cast<const char*>(value.data()), value.size()};
}
fs::path from_utf8(const std::string& text) {
  return fs::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()),
                                text.size()));
}
std::array<std::uint32_t, 4> version_parts(const std::string& text) {
  require(!text.empty() && text.size() <= 64, "Invalid version");
  std::array<std::uint32_t, 4> parts{};
  std::size_t start = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    auto end = text.find('.', start);
    if (end == std::string::npos) end = text.size();
    require(end > start && end - start <= 10, "Invalid version component");
    for (std::size_t j = start; j < end; ++j)
      require(text[j] >= '0' && text[j] <= '9', "Invalid version");
    const auto result =
        std::from_chars(text.data() + start, text.data() + end, parts[i]);
    require(result.ec == std::errc{}, "Version component overflow");
    if (i == 3)
      require(end == text.size(), "Too many version components");
    else
      require(end != text.size(), "Expected four version components");
    start = end + 1;
  }
  return parts;
}
Json parse_json(const std::string& text) {
  require(text.size() <= 1024 * 1024, "JSON exceeds size limit");
  std::vector<std::set<std::string>> keys(34);
  try {
    return Json::parse(
        text, [&keys](int depth, Json::parse_event_t event, Json& value) {
          require(depth >= 0 && depth <= 32, "JSON nesting limit exceeded");
          const auto index = static_cast<std::size_t>(depth);
          if (event == Json::parse_event_t::object_start)
            keys.at(index + 1).clear();
          if (event == Json::parse_event_t::key)
            require(keys.at(index).insert(value.get<std::string>()).second,
                    "Duplicate JSON key");
          return true;
        });
  } catch (const Json::exception&) {
    throw Error("Malformed JSON", Code::security);
  }
}
std::string hex(std::span<const unsigned char> data) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (auto byte : data) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}
Bytes unhex(const std::string& text) {
  require(text.size() == 64, "Expected SHA-256 in hexadecimal format");
  const auto normalized = lower(text);
  Bytes out;
  auto digit = [](char c) -> unsigned char {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    throw Error("Invalid hexadecimal hash", Code::security);
  };
  for (std::size_t i = 0; i < text.size(); i += 2)
    out.push_back(static_cast<unsigned char>((digit(normalized[i]) << 4) |
                                             digit(normalized[i + 1])));
  return out;
}
Options parse_options(const std::vector<std::string>& args) {
  Options o;
  std::set<std::string> seen;
  for (std::size_t i = 0; i < args.size(); ++i) {
    auto flag = args[i];
    require(seen.insert(flag).second, "Repeated option: " + flag,
            Code::invalid);
    auto value = [&]() {
      require(i + 1 < args.size() && !args[i + 1].starts_with("--"),
              "Missing value for " + flag, Code::invalid);
      return args[++i];
    };
    if (flag == "--help" || flag == "-h")
      o.help = true;
    else if (flag == "--version")
      o.version = true;
    else if (flag == "--check")
      o.check = true;
    else if (flag == "--dry-run")
      o.dry_run = true;
    else if (flag == "--restore")
      o.restore = true;
    else if (flag == "--verbose" || flag == "--debug")
      o.verbose = true;
    else if (flag == "--force-download")
      o.force = true;
    else if (flag == "--helium-path")
      o.target = from_utf8(value());
    else if (flag == "--chrome-path")
      o.chrome = from_utf8(value());
    else if (flag == "--package")
      o.package = from_utf8(value());
    else if (flag == "--source")
      o.source = value();
    else
      throw Error("Unknown option: " + flag, Code::invalid);
  }
  require(static_cast<int>(o.check) + static_cast<int>(o.dry_run) +
                  static_cast<int>(o.restore) <=
              1,
          "Choose one of --check, --dry-run or --restore", Code::invalid);
  require(o.source == "google" || o.source == "chrome" || o.source == "package",
          "Invalid source", Code::invalid);
  require(o.chrome.empty() || o.source == "chrome",
          "--chrome-path requires --source chrome", Code::invalid);
  require((o.source == "package") == !o.package.empty(),
          "--source package requires --package", Code::invalid);
  require(!o.force ||
              (o.source == "google" && !o.check && !o.dry_run && !o.restore),
          "--force-download is only valid for an active Google installation",
          Code::invalid);
  return o;
}
std::string help_text() {
  return "Helium DRM Fixer " FIXER_VERSION
         " (Windows 11 / Linux x86_64)\n"
         "Usage: helium_drm_fixer [options]\n"
         "  --check                 Inspect local CDM; no network or writes\n"
         "  --dry-run               Show planned actions; no network or "
         "writes\n"
         "  --restore               Recover an interrupted install or restore "
         "backup\n"
         "  --helium-path PATH      Exact WidevineCdm root (not Helium "
         "application root)\n"
         "  --source google|chrome|package  Default: google; no silent "
         "fallback\n"
         "  --chrome-path PATH      Source CDM directory; requires --source "
         "chrome\n"
         "  --package FILE          Signed CRX3; requires --source package\n"
         "  --force-download        Ignore the verified package cache\n"
         "  --verbose, --debug      Show source and target details\n"
         "  --help, --version\n"
         "Close Helium before install/restore. Existing CDM is backed up.\n"
         "Local Chrome files are trusted by your explicit source selection.\n";
}
int run(const Options& o) {
  if (o.help) {
    std::cout << help_text();
    return 0;
  }
  if (o.version) {
    std::cout << FIXER_VERSION << '\n';
    return 0;
  }
  auto target = o.target.empty() ? detect_target()
                                 : fs::absolute(o.target).lexically_normal();
  require(target.filename() == "WidevineCdm",
          "Target must be the exact WidevineCdm directory", Code::invalid);
  assert_safe_path(target);
  if (o.verbose || o.dry_run) std::cout << "Target: " << utf8(target) << '\n';
  if (o.check) {
    if (has_transaction(target)) {
      std::cout << "Pending recovery: run --restore before installing.\n";
      return 5;
    }
    if (!fs::exists(target)) {
      std::cout << "Widevine is missing.\n";
      return 3;
    }
    try {
      auto cdm = read_cdm(installed_cdm_dir(target));
      std::cout << "Widevine " << cdm.version
                << ": manifest and x86_64 library are locally valid.\n"
                   "Publisher integrity and streaming compatibility are not "
                   "established by this check.\n";
      return 0;
    } catch (const Error& error) {
      std::cout << "Widevine is locally invalid: " << error.what() << '\n';
      return 4;
    }
  }
  if (o.dry_run) {
    std::cout << "Read-only plan. Source: " << o.source << ".\n";
    if (o.source == "chrome") {
      const auto source = o.chrome.empty() ? detect_chrome() : o.chrome;
      const auto cdm = read_cdm(source);
      std::cout << "Local source version: " << cdm.version
                << " (not publisher-verified).\n";
    } else if (o.source == "package") {
      const auto cdm = verify_crx(read_file(o.package, package_limit));
      std::cout << "Signed source version: " << cdm.version << '\n';
    } else
      std::cout << "Online version unknown: no request is made in this mode.\n";
    std::cout << "Would verify source, stage files, back up current CDM, "
                 "install and check.\n";
    if (has_transaction(target))
      std::cout << "Blocked by pending transaction; --restore is required.\n";
    return 0;
  }
  ensure_browser_closed();
  if (o.restore) {
    restore_cdm(target);
    std::cout << "Recovery/restore completed. Restart Helium.\n";
    return 0;
  }
  require(!has_transaction(target), "Pending transaction: use --restore first",
          Code::recovery);
  Cdm cdm;
  if (o.source == "google")
    cdm = acquire_google(o.force);
  else if (o.source == "package")
    cdm = verify_crx(read_file(o.package, package_limit));
  else {
    const auto source =
        o.chrome.empty() ? detect_chrome() : fs::absolute(o.chrome);
    assert_safe_path(source, false);
    const auto s = fs::weakly_canonical(source),
               t = fs::weakly_canonical(target);
    auto relative = s.lexically_relative(t);
    require(s != t && (s.root_name() != t.root_name() ||
                       (!relative.empty() && *relative.begin() == "..")),
            "Source must be outside the target");
    cdm = read_cdm(source);
    cdm.origin = "explicit local Chrome source (not publisher-verified)";
  }
  check_cancelled();
  if (o.verbose)
    std::cout << "Source: " << cdm.origin << "\nVersion: " << cdm.version
              << '\n';
  install_cdm(target, cdm);
  std::cout
      << "Installed Widevine " << cdm.version
      << ". Previous installation retained as backup.\n"
         "Restart Helium. Streaming service compatibility is not guaranteed.\n";
  return 0;
}
}  // namespace fixer
