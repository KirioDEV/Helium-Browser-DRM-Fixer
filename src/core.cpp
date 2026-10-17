#include <algorithm>
#include <charconv>
#include <iostream>
#include <set>

#include "app_update.hpp"
#include "fixer.hpp"

namespace fixer {
std::atomic_bool cancelled{false};
static_assert(std::atomic_bool::is_always_lock_free,
              "Signal cancellation requires lock-free atomics");

void check_cancelled() {
  if (cancelled.load()) throw Error("Operation cancelled", Code::cancelled);
}

std::string lower(std::string value) {
  for (char &c : value)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
  return value;
}

std::string utf8(const fs::path &path) {
  const auto value = path.u8string();
  return {reinterpret_cast<const char *>(value.data()), value.size()};
}

fs::path from_utf8(const std::string &text) {
  return fs::path(std::u8string(reinterpret_cast<const char8_t *>(text.data()),
                                text.size()));
}

std::array<std::uint32_t, 4> version_parts(const std::string &text) {
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

Json parse_json(const std::string &text) {
  require(text.size() <= 1024 * 1024, "JSON exceeds size limit");
  std::vector<std::set<std::string> > keys(34);
  try {
    return Json::parse(
        text, [&keys](int depth, Json::parse_event_t event, Json &value) {
          require(depth >= 0 && depth <= 32, "JSON nesting limit exceeded");
          const auto index = static_cast<std::size_t>(depth);
          if (event == Json::parse_event_t::object_start)
            keys.at(index + 1).clear();
          if (event == Json::parse_event_t::key)
            require(keys.at(index).insert(value.get<std::string>()).second,
                    "Duplicate JSON key");
          return true;
        });
  } catch (const Json::exception &) {
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

Bytes unhex(const std::string &text) {
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

Options parse_options(const std::vector<std::string> &args) {
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
    else if (flag == "--check-app-update")
      o.check_app_update = true;
    else if (flag == "--update-app")
      o.update_app = true;
    else if (flag == "--restore-app") {
      o.restore_app = from_utf8(value());
      require(!o.restore_app.empty(), "Empty app restore target",
              Code::invalid);
    } else if (flag == "--app-update-status") {
      o.app_update_status = from_utf8(value());
      require(!o.app_update_status.empty(), "Empty app update job",
              Code::invalid);
    } else if (flag == "--verify-app-release") {
      o.verify_app_release = from_utf8(value());
      require(!o.verify_app_release.empty(), "Empty app release package",
              Code::invalid);
    } else if (flag == "--json")
      o.json = true;
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
    else if (flag == "--helium-app-path") {
      o.helium_app = from_utf8(value());
      require(!o.helium_app.empty(), "Empty Helium application path",
              Code::invalid);
    } else if (flag == "--chrome-path")
      o.chrome = from_utf8(value());
    else if (flag == "--package")
      o.package = from_utf8(value());
    else if (flag == "--source")
      o.source = value();
    else
      throw Error("Unknown option: " + flag, Code::invalid);
  }
  validate_options(o);
  return o;
}

void validate_options(const Options &o) {
  const auto app_modes = static_cast<int>(o.check_app_update) +
                         static_cast<int>(o.update_app) +
                         static_cast<int>(!o.restore_app.empty()) +
                         static_cast<int>(!o.app_update_status.empty()) +
                         static_cast<int>(!o.verify_app_release.empty());
  require(app_modes <= 1, "Choose one app update operation", Code::invalid);
  require(app_modes == 0 ||
              (!o.check && !o.dry_run && !o.restore && !o.force &&
               o.target.empty() && o.helium_app.empty() && o.chrome.empty() &&
               o.package.empty() && o.source == "google"),
          "App update operations cannot be combined with CDM options",
          Code::invalid);
  require(static_cast<int>(o.check) + static_cast<int>(o.dry_run) +
                  static_cast<int>(o.restore) <=
              1,
          "Choose one of --check, --dry-run or --restore", Code::invalid);
  require(o.source == "google" || o.source == "chrome" || o.source == "package",
          "Invalid source", Code::invalid);
  require(!o.json || o.check || o.check_app_update ||
              !o.app_update_status.empty() || !o.verify_app_release.empty(),
          "--json requires an inspection command", Code::invalid);
  require(
      o.helium_app.empty() || (o.target.empty() && !o.restore),
      "--helium-app-path cannot be combined with --helium-path or --restore; "
      "restore requires the exact WidevineCdm root",
      Code::invalid);
  require(o.chrome.empty() || o.source == "chrome",
          "--chrome-path requires --source chrome", Code::invalid);
  require((o.source == "package") == !o.package.empty(),
          "--source package requires --package", Code::invalid);
  require(!o.force ||
              (o.source == "google" && !o.check && !o.dry_run && !o.restore),
          "--force-download is only valid for an active Google installation",
          Code::invalid);
}

std::string help_text() {
  return "Helium DRM Fixer " FIXER_VERSION
         " (Windows 11 / Linux x86_64)\n"
         "Usage: helium_drm_fixer [options]\n"
         "  --check                 Inspect local CDM; no network or writes\n"
         "  --check-app-update      Online app release check; no installation\n"
         "  --update-app            Download signed app update; schedule "
         "replacement on exit\n"
         "  --restore-app PATH      Schedule recovery of the exact app "
         "executable\n"
         "  --app-update-status JOB Read the helper job result (also with "
         "--json)\n"
         "  --verify-app-release ZIP Verify local signed release; no network "
         "or writes\n"
         "  --json                  JSON result for --check or "
         "--check-app-update, --app-update-status or --verify-app-release\n"
         "  --dry-run               Show planned actions; no network or "
         "writes\n"
         "  --restore               Recover an interrupted install or restore "
         "backup\n"
         "  --helium-path PATH      Exact WidevineCdm root (not Helium "
         "application root)\n"
         "  --helium-app-path PATH  Windows application/version directory; "
         "select highest installed version (not for restore)\n"
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

fs::path resolve_target(const Options &o) {
  require(o.helium_app.empty() || (o.target.empty() && !o.restore),
          "Application path conflicts with exact target or restore",
          Code::invalid);
  const auto target = !o.helium_app.empty() ? resolve_helium_app(o.helium_app)
                      : o.target.empty()
                          ? detect_target()
                          : fs::absolute(o.target).lexically_normal();
  require(target.filename() == "WidevineCdm",
          "Target must be the exact WidevineCdm directory", Code::invalid);
  assert_safe_path(target);
  return target;
}

int run(const Options &o) {
  validate_options(o);
  if (o.help) {
    std::cout << help_text();
    return 0;
  }
  if (o.version) {
    std::cout << FIXER_VERSION << '\n';
    return 0;
  }
  if (!o.app_update_status.empty()) {
    const auto result = app_update_job_status(
        fs::absolute(o.app_update_status).lexically_normal());
    if (o.json)
      std::cout << result.dump() << '\n';
    else
      std::cout << result.at("state").get<std::string>() << ": "
                << result.at("detail").get<std::string>() << '\n';
    return result.at("exit_code").get<int>();
  }
  if (!o.verify_app_release.empty()) {
    const auto result = inspect_app_release(o.verify_app_release);
    if (o.json)
      std::cout << result.dump() << '\n';
    else
      std::cout << "Verified signed app release "
                << result.at("version").get<std::string>() << " ("
                << result.at("platform").get<std::string>()
                << "). No installation performed.\n";
    return 0;
  }
  if (o.update_app || !o.restore_app.empty()) {
    fs::path job;
    if (o.update_app) {
      require(app_self_update_supported(),
              "App self-updates require a configured signing key and a "
              "standalone build");
      const auto target = app_executable_path();
      const auto hash = sha256(read_file(target, file_limit));
      const auto prepared = prepare_app_update(app_update_jobs(target));
      job =
          start_app_update(prepared.directory, prepared.manifest.version, hash);
    } else {
      job = start_app_restore(fs::absolute(o.restore_app).lexically_normal());
    }
    std::cout << "App operation scheduled; helper will apply it after this "
                 "process exits.\n"
              << "Job: " << utf8(job) << '\n'
              << "Inspect with --app-update-status JOB --json.\n"
              << "Recovery helper: "
              << utf8(job /
#ifdef _WIN32
                      "update-helper.exe"
#else
                      "update-helper"
#endif
                      )
              << '\n';
    return 0;
  }
  if (o.check_app_update) {
    const auto status = check_app_update();
    if (o.json)
      std::cout << app_update_json(status).dump() << '\n';
    else {
      std::cout << "Installed app version: " << status.installed_version
                << '\n';
      switch (status.state) {
        case AppUpdateState::update_available:
          std::cout
              << "New app release: " << status.available_version << '\n'
              << status.release_url << '\n'
              << "Release metadata only; package integrity is not verified. "
                 "Use --update-app for a signature-verified update.\n";
          break;
        case AppUpdateState::current:
          std::cout
              << "Installed app version matches the latest stable release.\n";
          break;
        case AppUpdateState::installed_newer:
          std::cout << "Installed app version is newer than the latest stable "
                       "release; no downgrade.\n";
          break;
        case AppUpdateState::no_public_release:
          std::cout << "No public stable app release accessible (HTTP 404); "
                       "the repository may also be unavailable.\n";
          break;
        case AppUpdateState::no_compatible_package:
          std::cout << "Release " << status.available_version
                    << " has no matching C++ app package for this platform.\n";
          break;
      }
    }
    return status.exit_code;
  }
  if (o.check) {
    const auto status = inspect_local(o);
    if (o.json) {
      std::cout << local_status_json(status).dump() << '\n';
      return status.exit_code;
    }
    if (o.verbose && !status.target.empty())
      std::cout << "Target: " << utf8(status.target) << '\n';
    switch (status.state) {
      case LocalState::recovery_required:
        std::cout << "Pending recovery: run --restore before installing.\n";
        break;
      case LocalState::missing:
        std::cout << "Widevine is missing.\n";
        break;
      case LocalState::locally_valid:
        std::cout << "Widevine " << status.version
                  << ": manifest and x86_64 library are locally valid.\n"
                     "Publisher integrity and streaming compatibility are not "
                     "established by this check.\n";
        break;
      case LocalState::locally_invalid:
        std::cout << "Widevine is locally invalid: " << status.detail << '\n';
        break;
      case LocalState::unavailable:
        std::cout << "Local inspection failed: " << status.detail << '\n';
        break;
    }
    return status.exit_code;
  }
  if (o.dry_run) {
    const auto target = resolve_target(o);
    std::cout << "Target: " << utf8(target) << '\n';
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
  const auto result = execute_operation(o, [&](const ProgressEvent &event) {
    switch (event.phase) {
      case ProgressPhase::target_resolved:
        if (o.verbose) std::cout << "Target: " << utf8(event.target) << '\n';
        break;
      case ProgressPhase::checking_source:
        std::cout << "Checking installation source...\n";
        break;
      case ProgressPhase::querying_release:
        std::cout << "Querying Google for Widevine...\n";
        break;
      case ProgressPhase::checking_cache:
        std::cout << "Rechecking cached package...\n";
        break;
      case ProgressPhase::downloading_package:
        std::cout << "Downloading and verifying Widevine " << event.version
                  << "...\n";
        break;
      case ProgressPhase::trusting_local_source:
        std::cout << "Using explicitly trusted local Chrome files; publisher "
                     "integrity is not verified.\n";
        break;
      case ProgressPhase::source_ready:
        if (o.verbose)
          std::cout << "Source: " << event.source
                    << "\nVersion: " << event.version << '\n';
        break;
      case ProgressPhase::preparing:
        std::cout << "Preparing Widevine " << event.version << "...\n";
        break;
      case ProgressPhase::preserving_previous:
        std::cout << "Prepared files checked; preserving any existing "
                     "installation...\n";
        break;
      case ProgressPhase::installing:
        std::cout << "Installing prepared files...\n";
        break;
      case ProgressPhase::verifying_installation:
        std::cout << "Checking installed files...\n";
        break;
      case ProgressPhase::restoring:
        std::cout << "Restoring the managed installation...\n";
        break;
      default:
        break;
    }
  });
  if (result.restored)
    std::cout << "Recovery/restore completed. Restart Helium.\n";
  else
    std::cout << "Installed Widevine " << result.version
              << ". Use --restore to restore the previous state.\n"
                 "Restart Helium. Streaming service compatibility is not "
                 "guaranteed.\n";
  return 0;
}
}  // namespace fixer
