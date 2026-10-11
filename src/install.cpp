#include <iostream>
#include <set>

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

        void check_marker(const fs::path &state, const fs::path &target) {
            assert_safe_path(state, false);
            const auto marker = parse_json(text(read_file(state / "owner.json", 4096)));
            require(marker == Json{{"format", 1}, {"target", utf8(target)}},
                    "Unrecognized managed state directory");
        }

        void init_state(const fs::path &state, const fs::path &target) {
            if (fs::exists(state)) {
                create_private_dir(state);
                check_marker(state, target);
            } else {
                create_private_dir(state);
                write_text(state / "owner.json",
                           Json{{"format", 1}, {"target", utf8(target)}}.dump());
                sync_dir(state);
            }
        }

        Json inventory(const fs::path &root) {
            assert_safe_path(root, false);
            require(fs::is_directory(root), "CDM root is not a directory");
            Json files = Json::object();
            std::uintmax_t total = 0;
            std::size_t count = 0;
            for (const auto &entry: fs::recursive_directory_iterator(root)) {
                assert_safe_path(entry.path(), false);
                require(++count <= 1024, "Existing CDM has too many entries");
                if (entry.is_directory()) continue;
                require(entry.is_regular_file(), "Non-regular file in CDM tree");
                const auto bytes = read_file(entry.path(), file_limit);
                require(bytes.size() <= expanded_limit - total,
                        "Existing CDM exceeds backup validation limit");
                total += bytes.size();
                const auto relative =
                        entry.path().lexically_relative(root).generic_u8string();
                files[std::string(reinterpret_cast<const char *>(relative.data()),
                                  relative.size())] = sha256(bytes);
            }
            return files;
        }

        Json read_journal(const fs::path &state, const fs::path &target) {
            check_marker(state, target);
            auto journal =
                    parse_json(text(read_file(state / "journal.json", 1024 * 1024)));
            try {
                require(journal.at("format") == 1 && journal.at("target") == utf8(target),
                        "Journal target/format mismatch");
                const auto id = journal.at("id").get<std::string>();
                require(id.size() == 32 &&
                        id.find_first_not_of("0123456789abcdef") == std::string::npos,
                        "Invalid transaction ID");
                const auto phase = journal.at("phase").get<std::string>();
                const std::set<std::string> phases{
                    "prepared", "old_moved", "new_moved",
                    "committed", "restoring", "restored"
                };
                require(phases.contains(phase) && journal.at("had_old").is_boolean() &&
                        journal.at("old_files").is_object() &&
                        journal.at("new_files").is_object(),
                        "Invalid transaction journal");
            } catch (const Json::exception &) {
                throw Error("Malformed transaction journal", Code::security);
            }
            return journal;
        }

        void save(const fs::path &state, Json &journal, const std::string &phase) {
            journal["phase"] = phase;
            replace_text(state / "journal.json", journal.dump());
        }

        void restore_locked(const fs::path &target, const fs::path &state) {
            auto journal = read_journal(state, target);
            const auto id = journal["id"].get<std::string>();
            const auto backup = state / ("backup-" + id);
            const auto stage = state / ("stage-" + id);
            const auto reverted = state / ("reverted-" + id);
            const bool had_old = journal["had_old"].get<bool>();
            const auto phase = journal["phase"].get<std::string>();
            if (phase == "restored") return;
            // Reconcile filesystem state as well as the journal: a crash can occur after
            // rename but before the next persisted phase. Never overwrite or delete an
            // unknown tree.
            if (had_old && fs::exists(backup))
                require(inventory(backup) == journal["old_files"],
                        "Backup contents changed; refusing restore", Code::recovery);
            if (fs::exists(target)) {
                const auto current = inventory(target);
                if (had_old && !fs::exists(backup) && current == journal["old_files"]) {
                    save(state, journal, "restored");
                    return;
                }
                if (phase == "prepared" && !had_old && fs::exists(stage)) {
                    throw Error("Unexpected target during recovery; refusing to move it",
                                Code::recovery);
                }
                require(current == journal["new_files"],
                        "Installed files changed; preserve them manually before restore",
                        Code::recovery);
                if (had_old)
                    require(fs::exists(backup), "Expected backup is missing", Code::recovery);
                require(!fs::exists(reverted), "Recovery destination exists",
                        Code::recovery);
                save(state, journal, "restoring");
                durable_rename(target, reverted);
            } else {
                require(!had_old || fs::exists(backup),
                        "Original installation and backup are both missing",
                        Code::recovery);
                save(state, journal, "restoring");
            }
            if (had_old) durable_rename(backup, target);
            save(state, journal, "restored");
            // Prepared/reverted trees remain private and recoverable; nothing is
            // recursively deleted.
        }
    } // namespace
    bool has_transaction(const fs::path &target) {
        const auto state = state_path(target);
        if (!fs::exists(state)) return false;
        check_marker(state, target);
        if (!fs::exists(state / "journal.json")) return false;
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
        (void) version_parts(utf8(path.filename()));
        return path;
#endif
    }

    void install_cdm(const fs::path &target, const Cdm &cdm,
                     const InstallHooks &hooks) {
        target_valid(target);
        (void) version_parts(cdm.version);
        validate_binary(cdm.library);
        const auto manifest = parse_json(text(cdm.manifest));
        require(manifest.at("version") == cdm.version &&
                cdm.manifest.size() <= 65536 && cdm.license.size() <= 1024 * 1024,
                "Invalid source manifest or license size");
        const auto state = state_path(target);
        init_state(state, target);
        Lock lock(state / "install.lock");
        require(!has_transaction(target), "Pending transaction: use --restore",
                Code::recovery);
        const auto space = fs::space(target.parent_path());
        require(space.available >= cdm.manifest.size() + cdm.library.size() +
                cdm.license.size() + 1024 * 1024,
                "Insufficient free space", Code::failure);
        const auto id = random_id();
        const auto stage = state / ("stage-" + id), backup = state / ("backup-" + id);
        create_private_dir(stage);
        auto data_dir = stage;
#ifndef _WIN32
        data_dir /= cdm.version;
        create_private_dir(data_dir);
#endif
        create_private_dir(data_dir / "_platform_specific");
        create_private_dir(data_dir / "_platform_specific" /
                           (platform_name() + "_x64"));
        write_file(data_dir / "manifest.json", cdm.manifest);
        write_file(data_dir / "_platform_specific" / (platform_name() + "_x64") /
                   binary_name(),
                   cdm.library);
        if (!cdm.license.empty()) write_file(data_dir / "LICENSE", cdm.license);
        require(read_cdm(data_dir).version == cdm.version,
                "Staged CDM validation failed");
#ifndef _WIN32
        write_text(stage / "latest-component-updated-widevine-cdm",
                   Json{{"Path", utf8(target / cdm.version)}}.dump());
#endif
        sync_dir(data_dir / "_platform_specific" / (platform_name() + "_x64"));
        sync_dir(data_dir / "_platform_specific");
        sync_dir(data_dir);
        sync_dir(stage);
        const bool had_old = fs::exists(target);
        Json journal{
            {"format", 1},
            {"id", id},
            {"target", utf8(target)},
            {"had_old", had_old},
            {"old_files", had_old ? inventory(target) : Json::object()},
            {"new_files", inventory(stage)},
            {"phase", "prepared"}
        };
        check_cancelled();
        if (fs::exists(state / "journal.json")) {
            const auto previous = read_journal(state, target);
            const auto history =
                    state / ("history-" + previous["id"].get<std::string>() + ".json");
            if (!fs::exists(history)) write_text(history, previous.dump());
        }
        save(state, journal, "prepared");
        auto phase = [&](const std::string &name) {
            if (hooks.phase) hooks.phase(name);
            check_cancelled();
        };
        try {
            phase("prepared");
            if (had_old) durable_rename(target, backup);
            phase("old_renamed"); // Deliberately before journal update, for
            // crash-injection tests.
            save(state, journal, "old_moved");
            phase("old_moved");
            durable_rename(stage, target);
            phase("new_renamed");
            save(state, journal, "new_moved");
            phase("new_moved");
            require(inventory(target) == journal["new_files"] &&
                    read_cdm(installed_cdm_dir(target)).version == cdm.version,
                    "Installed CDM validation failed");
            save(state, journal, "committed");
        } catch (...) {
            const auto original = std::current_exception();
            try {
                restore_locked(target, state);
            } catch (const std::exception &error) {
                throw Error(
                    std::string("Installation interrupted; automatic recovery failed: ") +
                    error.what() + ". Backup/journal retained. Use --restore.",
                    Code::recovery);
            }
            std::rethrow_exception(original);
        }
    }

    void restore_cdm(const fs::path &target) {
        target_valid(target);
        const auto state = state_path(target);
        require(fs::exists(state), "No managed backup found", Code::missing);
        check_marker(state, target);
        Lock lock(state / "install.lock");
        restore_locked(target, state);
    }
} // namespace fixer
