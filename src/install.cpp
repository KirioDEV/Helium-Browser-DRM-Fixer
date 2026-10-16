#include <iostream>
#include <optional>
#include <set>

#include "directory.hpp"
#include "fixer.hpp"

namespace fixer {
namespace {
std::string text(const Bytes &bytes) {
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

fs::path state_path(const fs::path &target) {
  return target.parent_path() / ".helium-drm-fixer";
}

void target_valid(const fs::path &target) {
  require(target.is_absolute() && target.filename() == "WidevineCdm" &&
              target.lexically_normal() == target,
          "Expected an absolute normalized WidevineCdm target");
  assert_safe_path(target);
  require(target.parent_path() != target.root_path(),
          "Installation directly under a filesystem root is rejected");
  require(fs::is_directory(target.parent_path()),
          "Target parent must already exist", Code::missing);
}

void check_marker(const Directory &state, const fs::path &target) {
  const auto marker = parse_json(text(state.read("owner.json", 4096)));
  require(marker == Json{{"format", 1}, {"target", utf8(target)}},
          "Unrecognized managed state directory");
}

Directory init_state(const Directory &parent, const fs::path &target) {
  const bool present = parent.exists(".helium-drm-fixer");
  parent.create_private(".helium-drm-fixer");
  auto state = parent.child(".helium-drm-fixer");
  if (present)
    check_marker(state, target);
  else {
    state.write_text("owner.json",
                     Json{{"format", 1}, {"target", utf8(target)}}.dump());
    state.sync();
  }
  return state;
}

Json read_journal(const Directory &state, const fs::path &target) {
  check_marker(state, target);
  auto journal = parse_json(text(state.read("journal.json", 1024 * 1024)));
  try {
    require(journal.at("format") == 1 && journal.at("target") == utf8(target),
            "Journal target/format mismatch");
    const auto id = journal.at("id").get<std::string>();
    require(id.size() == 32 &&
                id.find_first_not_of("0123456789abcdef") == std::string::npos,
            "Invalid transaction ID");
    const auto phase = journal.at("phase").get<std::string>();
    const std::set<std::string> phases{"prepared",  "old_moved", "new_moved",
                                       "committed", "restoring", "restored"};
    require(phases.contains(phase) && journal.at("had_old").is_boolean() &&
                journal.at("old_files").is_object() &&
                journal.at("new_files").is_object(),
            "Invalid transaction journal");
  } catch (const Json::exception &) {
    throw Error("Malformed transaction journal", Code::security);
  }
  return journal;
}

void save(const Directory &state, Json &journal, const std::string &phase) {
  journal["phase"] = phase;
  state.replace("journal.json", journal.dump());
}

void restore_locked(const fs::path &target, const Directory &parent,
                    const Directory &state, const InstallHooks &hooks = {},
                    bool require_location = false) {
  auto checkpoint = [&](const std::string &name) {
    if (hooks.phase) hooks.phase(name);
    if (require_location) {
      parent.verify_location();
      state.verify_location();
    }
  };
  auto journal = read_journal(state, target);
  const auto id = journal["id"].get<std::string>();
  const auto backup = "backup-" + id;
  const auto stage = "stage-" + id;
  const auto reverted = "reverted-" + id;
  const bool had_old = journal["had_old"].get<bool>();
  const auto phase = journal["phase"].get<std::string>();
  if (phase == "restored") return;
  // Reconcile filesystem state as well as the journal: a crash can occur after
  // rename but before the next persisted phase. Never overwrite or delete an
  // unknown tree.
  if (had_old && state.exists(backup))
    require(directory_inventory(state.child(backup)) == journal["old_files"],
            "Backup contents changed; refusing restore", Code::recovery);
  if (parent.exists("WidevineCdm")) {
    const auto current = directory_inventory(parent.child("WidevineCdm"));
    if (had_old && !state.exists(backup) && current == journal["old_files"]) {
      checkpoint("restore_validated");
      save(state, journal, "restored");
      return;
    }
    if (phase == "prepared" && !had_old && state.exists(stage)) {
      throw Error("Unexpected target during recovery; refusing to move it",
                  Code::recovery);
    }
    require(current == journal["new_files"],
            "Installed files changed; preserve them manually before restore",
            Code::recovery);
    if (had_old)
      require(state.exists(backup), "Expected backup is missing",
              Code::recovery);
    require(!state.exists(reverted), "Recovery destination exists",
            Code::recovery);
    checkpoint("restore_validated");
    save(state, journal, "restoring");
    parent.rename("WidevineCdm", state, reverted);
    checkpoint("restore_current_moved");
  } else {
    require(!had_old || state.exists(backup),
            "Original installation and backup are both missing",
            Code::recovery);
    checkpoint("restore_validated");
    save(state, journal, "restoring");
  }
  if (had_old) state.rename(backup, parent, "WidevineCdm");
  checkpoint("restore_backup_moved");
  save(state, journal, "restored");
  // Prepared/reverted trees remain private and recoverable; nothing is
  // recursively deleted.
}

Directory installed_directory(const Directory &parent, const fs::path &target) {
  const auto root = parent.child("WidevineCdm");
#ifdef _WIN32
  (void)target;
  return root;
#else
  const auto hint = parse_json(
      text(root.read("latest-component-updated-widevine-cdm", 4096)));
  require(hint.is_object() && hint.contains("Path") && hint["Path"].is_string(),
          "Invalid component hint file");
  const auto path = from_utf8(hint["Path"].get<std::string>());
  require(path.is_absolute() && path.parent_path() == target &&
              path.lexically_normal() == path,
          "Hint points outside CDM root");
  const auto version = utf8(path.filename());
  (void)version_parts(version);
  return root.child(version);
#endif
}
}  // namespace
bool has_transaction(const fs::path &target) {
  if (!fs::exists(state_path(target))) return false;
  const Directory parent(target.parent_path());
  const auto state = parent.child(".helium-drm-fixer");
  check_marker(state, target);
  if (!state.exists("journal.json")) return false;
  const auto journal = read_journal(state, target);
  return journal["phase"] != "committed" && journal["phase"] != "restored";
}

fs::path installed_cdm_dir(const fs::path &target) {
#ifdef _WIN32
  return target;
#else
  auto hint = parse_json(
      text(read_file(target / "latest-component-updated-widevine-cdm", 4096)));
  require(hint.is_object() && hint.contains("Path") && hint["Path"].is_string(),
          "Invalid component hint file");
  const auto path = from_utf8(hint["Path"].get<std::string>());
  require(path.is_absolute() && path.parent_path() == target &&
              path.lexically_normal() == path,
          "Hint points outside CDM root");
  (void)version_parts(utf8(path.filename()));
  return path;
#endif
}

void install_cdm(const fs::path &target, const Cdm &cdm,
                 const InstallHooks &hooks) {
  check_cancelled();
  target_valid(target);
  (void)version_parts(cdm.version);
  require(cdm.manifest.size() <= 65536 && cdm.library.size() <= file_limit &&
              cdm.license.size() <= 1024 * 1024,
          "Source files exceed size limits");
  validate_binary(cdm.library);
  const auto manifest = parse_json(text(cdm.manifest));
  require(manifest.is_object() && manifest.contains("version") &&
              manifest["version"].is_string() &&
              manifest["version"] == cdm.version,
          "Invalid source manifest version");
  const auto space = fs::space(target.parent_path());
  require(space.available != static_cast<std::uintmax_t>(-1) &&
              space.available <= space.capacity &&
              space.available >= cdm.manifest.size() + cdm.library.size() +
                                     cdm.license.size() + 1024 * 1024,
          "Insufficient free space", Code::failure);
  const Directory parent(target.parent_path());
  const auto state = init_state(parent, target);
  const auto lock = state.lock("install.lock");
  parent.verify_location();
  state.verify_location();
  if (state.exists("journal.json")) {
    const auto previous = read_journal(state, target);
    require(previous["phase"] == "committed" || previous["phase"] == "restored",
            "Pending transaction: use --restore", Code::recovery);
  }
  const auto id = random_id();
  const auto stage = "stage-" + id, backup = "backup-" + id;
  state.create_private(stage);
  std::optional<Directory> staging{state.child(stage)};
  {
    auto data_dir = *staging;
#ifndef _WIN32
    staging->create_private(cdm.version);
    data_dir = staging->child(cdm.version);
#endif
    data_dir.create_private("_platform_specific");
    const auto specific = data_dir.child("_platform_specific");
    specific.create_private(platform_name() + "_x64");
    const auto binaries = specific.child(platform_name() + "_x64");
    data_dir.write("manifest.json", cdm.manifest);
    if (hooks.phase) hooks.phase("staging");
    parent.verify_location();
    state.verify_location();
    staging->verify_location();
    check_cancelled();
    binaries.write(binary_name(), cdm.library);
    if (!cdm.license.empty()) data_dir.write("LICENSE", cdm.license);
    require(read_cdm(data_dir).version == cdm.version,
            "Staged CDM validation failed");
#ifndef _WIN32
    staging->write_text("latest-component-updated-widevine-cdm",
                        Json{{"Path", utf8(target / cdm.version)}}.dump());
#endif
    binaries.sync();
    specific.sync();
    data_dir.sync();
    staging->sync();
  }
  const bool had_old = parent.exists("WidevineCdm");
  Json journal{
      {"format", 1},
      {"id", id},
      {"target", utf8(target)},
      {"had_old", had_old},
      {"old_files", had_old ? directory_inventory(parent.child("WidevineCdm"))
                            : Json::object()},
      {"new_files", directory_inventory(*staging)},
      {"phase", "prepared"}};
  check_cancelled();
  parent.verify_location();
  state.verify_location();
  staging->verify_location();
  if (state.exists("journal.json")) {
    const auto previous = read_journal(state, target);
    const auto history =
        "history-" + previous["id"].get<std::string>() + ".json";
    if (!state.exists(history)) state.write_text(history, previous.dump());
  }
  save(state, journal, "prepared");
#ifdef _WIN32
  // Windows cannot rename a tree while directory enumeration handles within it
  // remain open. The stable transaction parent and state handles stay alive.
  staging.reset();
#endif
  auto phase = [&](const std::string &name) {
    if (hooks.phase) hooks.phase(name);
    parent.verify_location();
    state.verify_location();
    check_cancelled();
  };
  try {
    phase("prepared");
    if (staging) staging->verify_location();
    if (had_old) parent.rename("WidevineCdm", state, backup);
    phase("old_renamed");  // Deliberately before journal update, for
    // crash-injection tests.
    save(state, journal, "old_moved");
    phase("old_moved");
    if (staging) staging->verify_location();
    state.rename(stage, parent, "WidevineCdm");
    phase("new_renamed");
    save(state, journal, "new_moved");
    phase("new_moved");
    require(directory_inventory(parent.child("WidevineCdm")) ==
                    journal["new_files"] &&
                read_cdm(installed_directory(parent, target)).version ==
                    cdm.version,
            "Installed CDM validation failed");
    save(state, journal, "committed");
  } catch (...) {
    const auto original = std::current_exception();
    try {
      restore_locked(target, parent, state);
    } catch (const std::exception &error) {
      throw Error(
          std::string("Installation interrupted; automatic recovery failed: ") +
              error.what() + ". Backup/journal retained. Use --restore.",
          Code::recovery);
    }
    std::rethrow_exception(original);
  }
}

void restore_cdm(const fs::path &target, const InstallHooks &hooks) {
  target_valid(target);
  const Directory parent(target.parent_path());
  require(parent.exists(".helium-drm-fixer"), "No managed backup found",
          Code::missing);
  parent.create_private(".helium-drm-fixer");
  const auto state = parent.child(".helium-drm-fixer");
  check_marker(state, target);
  const auto lock = state.lock("install.lock");
  parent.verify_location();
  state.verify_location();
  restore_locked(target, parent, state, hooks, true);
}
}  // namespace fixer
