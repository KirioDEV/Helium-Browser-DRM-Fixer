#include "fixer.hpp"

namespace fixer {
void notify_progress(const ProgressObserver& observer, const ProgressEvent& event) noexcept {
    if (!observer)
        return;
    try {
        observer(event);
    } catch (...) {
        // Observer exceptions must not interrupt recovery or turn a committed
        // installation into a reported failure. Cancellation uses cancelled.
    }
}

OperationResult execute_operation(const Options& options, const ProgressObserver& observer) {
    validate_options(options);
    require(!options.check && !options.dry_run && !options.help && !options.version && !options.json &&
                    !options.check_app_update && !options.update_app && options.restore_app.empty() &&
                    options.app_update_status.empty() && options.verify_app_release.empty(),
            "Active operation does not accept inspection or help modes", Code::invalid);
    check_cancelled();
    OperationResult result{resolve_target(options), {}, options.restore};
    std::string origin;
    auto report = [&](ProgressPhase phase) {
        notify_progress(observer, {phase, result.target, result.version, origin});
    };
    report(ProgressPhase::target_resolved);
    check_cancelled();
    ensure_browser_closed();
    if (options.restore) {
        report(ProgressPhase::restoring);
        check_cancelled();
        restore_cdm(result.target, {{[&](const std::string& phase) {
                        if (phase == "restore_validated")
                            report(ProgressPhase::restore_validated);
                        else if (phase == "restore_current_moved")
                            report(ProgressPhase::restore_current_preserved);
                        else if (phase == "restore_backup_moved")
                            report(ProgressPhase::finalizing_restore);
                    }}});
    } else {
        require(!has_transaction(result.target), "Pending transaction: use --restore first", Code::recovery);
        report(ProgressPhase::checking_source);
        check_cancelled();
        Cdm cdm;
        if (options.source == "google") {
            cdm = acquire_google(options.force, [&](const ProgressEvent& progress) {
                auto event = progress;
                event.target = result.target;
                notify_progress(observer, event);
            });
        } else if (options.source == "package") {
            cdm = verify_crx(read_file(resolve_home_path(fs::absolute(options.package)), package_limit));
        } else {
            const auto source =
                    resolve_home_path(options.chrome.empty() ? detect_chrome() : fs::absolute(options.chrome));
            assert_safe_path(source, false);
            const auto s = fs::weakly_canonical(source), t = fs::weakly_canonical(result.target);
            const auto relative = s.lexically_relative(t);
            require(s != t && (s.root_name() != t.root_name() || (!relative.empty() && *relative.begin() == "..")),
                    "Source must be outside the target");
            cdm = read_cdm(source);
            cdm.origin = "explicit local Chrome source (not publisher-verified)";
        }
        result.version = cdm.version;
        origin = cdm.origin;
        if (options.source == "chrome")
            report(ProgressPhase::trusting_local_source);
        report(ProgressPhase::source_ready);
        check_cancelled();
        report(ProgressPhase::preparing);
        check_cancelled();
        install_cdm(result.target, cdm, {{[&](const std::string& phase) {
                        if (phase == "prepared")
                            report(ProgressPhase::preserving_previous);
                        else if (phase == "old_moved")
                            report(ProgressPhase::installing);
                        else if (phase == "new_moved")
                            report(ProgressPhase::verifying_installation);
                    }}});
    }
    // Do not reclassify a completed, persisted transaction as cancelled merely
    // because cancellation arrived at the final progress notification.
    report(ProgressPhase::completed);
    return result;
}
}  // namespace fixer
