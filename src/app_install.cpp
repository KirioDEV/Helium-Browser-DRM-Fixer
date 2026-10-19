#include <set>

#include "app_identity.hpp"
#include "app_update.hpp"
#include "directory.hpp"

namespace fixer {
namespace {
constexpr auto state_name = app_update_state_name;
constexpr auto executable_name = app_update_binary;

bool digest_valid(const std::string &value) {
  return value.size() == 64 &&
         value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

void target_valid(const fs::path &target) {
  require(target.is_absolute() && target.lexically_normal() == target &&
              target.filename() == executable_name &&
              target.parent_path() != target.root_path(),
          "Expected an absolute normalized app executable target");
  assert_safe_path(target);
}

Json read_json(const Directory &directory, const std::string &name) {
  const auto bytes = directory.read(name, 16384);
  return parse_json(std::string(bytes.begin(), bytes.end()));
}

void marker_valid(const Directory &state, const fs::path &target) {
  require(read_json(state, "owner.json") ==
              Json{{"format", 1}, {"target", utf8(target)}},
          "Unrecognized app update state directory");
}

Json read_journal(const Directory &state, const fs::path &target) {
  marker_valid(state, target);
  auto journal = read_json(state, "journal.json");
  try {
    const auto id = journal.at("id").get<std::string>();
    const std::set<std::string> phases{"prepared",  "old_moved", "new_moved",
                                       "committed", "restoring", "restored"};
    require(journal.at("format") == 1 && journal.at("target") == utf8(target) &&
                id.size() == 32 &&
                id.find_first_not_of("0123456789abcdef") == std::string::npos &&
                phases.contains(journal.at("phase").get<std::string>()) &&
                digest_valid(journal.at("old_sha256").get<std::string>()) &&
                digest_valid(journal.at("new_sha256").get<std::string>()) &&
                journal.at("old_sha256") != journal.at("new_sha256"),
            "Invalid app update journal", Code::recovery);
    (void)app_version_parts(journal.at("version").get<std::string>());
  } catch (const Json::exception &) {
    throw Error("Malformed app update journal", Code::recovery);
  }
  return journal;
}

void save(const Directory &state, Json &journal, const std::string &phase) {
  journal["phase"] = phase;
  state.replace("journal.json", journal.dump());
}

void hash_matches(const Directory &directory, const std::string &name,
                  const Json &expected) {
  require(
      sha256(directory.read(name, file_limit)) == expected.get<std::string>(),
      "App transaction file changed; preserving files for manual recovery",
      Code::recovery);
}

void locations(const Directory &parent, const Directory &state) {
  parent.verify_location();
  state.verify_location();
}

void restore_locked(const fs::path &target, const Directory &parent,
                    const Directory &state, const InstallHooks &hooks) {
  auto journal = read_journal(state, target);
  if (journal["phase"] == "restored") {
    hash_matches(parent, executable_name, journal["old_sha256"]);
    return;
  }
  const auto id = journal["id"].get<std::string>();
  const auto backup = "backup-" + id, reverted = "reverted-" + id;
  auto checkpoint = [&](const std::string &phase) {
    if (hooks.phase) hooks.phase(phase);
    locations(parent, state);
  };
  locations(parent, state);
  if (state.exists(backup)) hash_matches(state, backup, journal["old_sha256"]);
  if (parent.exists(executable_name)) {
    const auto current = sha256(parent.read(executable_name, file_limit));
    if (!state.exists(backup) &&
        current == journal["old_sha256"].get<std::string>()) {
      checkpoint("restore_validated");
      hash_matches(parent, executable_name, journal["old_sha256"]);
      save(state, journal, "restored");
      return;
    }
    require(current == journal["new_sha256"].get<std::string>() &&
                state.exists(backup) && !state.exists(reverted),
            "Unexpected app executable or missing backup; refusing recovery",
            Code::recovery);
    checkpoint("restore_validated");
    hash_matches(state, backup, journal["old_sha256"]);
    hash_matches(parent, executable_name, journal["new_sha256"]);
    save(state, journal, "restoring");
    parent.rename(executable_name, state, reverted);
    checkpoint("restore_current_moved");
  } else {
    require(state.exists(backup), "App executable and backup are both missing",
            Code::recovery);
    checkpoint("restore_validated");
    save(state, journal, "restoring");
  }
  hash_matches(state, backup, journal["old_sha256"]);
  locations(parent, state);
  state.rename(backup, parent, executable_name);
  checkpoint("restore_backup_moved");
  hash_matches(parent, executable_name, journal["old_sha256"]);
  save(state, journal, "restored");
}

void install(const VerifiedAppUpdate &update, const fs::path &target,
             const std::string &expected_old, const InstallHooks &hooks) {
  check_cancelled();
  target_valid(target);
  require(digest_valid(expected_old), "Invalid expected app executable hash");
  const AppPackageFile *executable = nullptr;
  for (const auto &file : update.files) {
    if (!file.path.starts_with("bin/")) continue;
    require(
        file.path == std::string("bin/") + executable_name && file.executable &&
            !executable,
        "App replacement requires a standalone package without runtime DLLs");
    executable = &file;
  }
  require(executable != nullptr, "App package executable is missing");
  const auto new_hash = sha256(executable->bytes);
  require(new_hash != expected_old, "App executable is already identical");
  const Directory parent(target.parent_path());
  require(sha256(parent.read(executable_name, file_limit)) == expected_old,
          "App executable changed since update was requested");
  const auto space = fs::space(target.parent_path());
  require(space.available != static_cast<std::uintmax_t>(-1) &&
              space.available >= executable->bytes.size() + 1024 * 1024,
          "Insufficient free space for app replacement", Code::failure);
  const bool present = parent.exists(state_name);
  parent.create_private(state_name);
  const auto state = parent.child(state_name);
  if (present) marker_valid(state, target);
  const auto lock = state.lock("update.lock");
  locations(parent, state);
  if (present)
    marker_valid(state, target);
  else
    state.write_text("owner.json",
                     Json{{"format", 1}, {"target", utf8(target)}}.dump());
  if (state.exists("journal.json")) {
    const auto previous = read_journal(state, target);
    require(previous["phase"] == "committed" || previous["phase"] == "restored",
            "Pending app transaction requires recovery first", Code::recovery);
    const auto history =
        "history-" + previous["id"].get<std::string>() + ".json";
    if (state.exists(history)) {
      auto archived = read_json(state, history);
      require(archived.at("phase") == "committed" ||
                  archived.at("phase") == "restored",
              "Invalid archived app transaction phase", Code::recovery);
      // An attempt can archive a committed journal and fail before replacing
      // it. A subsequent explicit rollback legitimately changes its phase.
      archived["phase"] = previous["phase"];
      require(archived == previous, "App transaction history changed",
              Code::recovery);
    } else
      state.write_text(history, previous.dump());
  }
  const auto id = random_id();
  const auto stage = "stage-" + id, backup = "backup-" + id;
  state.write(stage, executable->bytes, true);
  auto checkpoint = [&](const std::string &phase) {
    if (hooks.phase) hooks.phase(phase);
    locations(parent, state);
    check_cancelled();
  };
  checkpoint("staging");
  hash_matches(state, stage, new_hash);
  hash_matches(parent, executable_name, expected_old);
  Json journal{{"format", 1},
               {"target", utf8(target)},
               {"id", id},
               {"version", update.manifest.version},
               {"old_sha256", expected_old},
               {"new_sha256", new_hash}};
  // A rename may succeed even if its subsequent directory flush fails. From
  // this point onward every error must reconcile actual files with the journal.
  try {
    save(state, journal, "prepared");
    checkpoint("prepared");
    hash_matches(state, stage, new_hash);
    hash_matches(parent, executable_name, expected_old);
    parent.rename(executable_name, state, backup);
    checkpoint("old_renamed");
    hash_matches(state, backup, expected_old);
    save(state, journal, "old_moved");
    checkpoint("old_moved");
    hash_matches(state, stage, new_hash);
    state.rename(stage, parent, executable_name);
    checkpoint("new_renamed");
    save(state, journal, "new_moved");
    checkpoint("new_moved");
    hash_matches(parent, executable_name, new_hash);
    hash_matches(state, backup, expected_old);
    save(state, journal, "committed");
  } catch (...) {
    const auto original = std::current_exception();
    try {
      locations(parent, state);
      if (state.exists("journal.json") &&
          read_journal(state, target)["id"] == id)
        restore_locked(target, parent, state, {});
    } catch (const std::exception &) {
      throw Error("App rollback failed; preserve state and backup for recovery",
                  Code::recovery);
    }
    std::rethrow_exception(original);
  }
}
}  // namespace

void install_prepared_app_update(const fs::path &directory,
                                 const std::string &expected_version,
                                 const fs::path &target,
                                 const std::string &expected_old_sha256,
                                 const InstallHooks &hooks) {
  install(read_prepared_app_update(directory, expected_version), target,
          expected_old_sha256, hooks);
}

void install_prepared_app_update_with_trusted_key(
    const fs::path &directory, const std::string &expected_version,
    const fs::path &target, const std::string &expected_old_sha256,
    std::span<const unsigned char> trusted_key, const InstallHooks &hooks) {
  install(read_prepared_app_update_with_trusted_key(directory, expected_version,
                                                    trusted_key),
          target, expected_old_sha256, hooks);
}

void restore_app_update(const fs::path &target, const InstallHooks &hooks) {
  target_valid(target);
  const Directory parent(target.parent_path());
  const auto state = parent.child(state_name);
  assert_private_dir(target.parent_path() / state_name);
  marker_valid(state, target);
  const auto lock = state.lock("update.lock");
  locations(parent, state);
  restore_locked(target, parent, state, hooks);
}
}  // namespace fixer
