#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "app-window.h"
#include "app_update.hpp"
#include "fixer.hpp"
#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

namespace {
using fixer::LocalState;
using fixer::ProgressPhase;

const char* phase_text(ProgressPhase phase) {
  switch (phase) {
    case ProgressPhase::target_resolved:
      return "Destination checked.";
    case ProgressPhase::checking_source:
      return "Checking installation source…";
    case ProgressPhase::querying_release:
      return "Querying Google for Widevine…";
    case ProgressPhase::checking_cache:
      return "Rechecking cached package…";
    case ProgressPhase::downloading_package:
      return "Downloading and verifying Widevine…";
    case ProgressPhase::trusting_local_source:
      return "Local source selected.";
    case ProgressPhase::source_ready:
      return "Source verified.";
    case ProgressPhase::preparing:
      return "Preparing files…";
    case ProgressPhase::preserving_previous:
      return "Backing up the current state…";
    case ProgressPhase::installing:
      return "Installing Widevine…";
    case ProgressPhase::verifying_installation:
      return "Checking installed files…";
    case ProgressPhase::restoring:
      return "Restoring the previous state…";
    case ProgressPhase::restore_validated:
      return "Restore validated…";
    case ProgressPhase::restore_current_preserved:
      return "Current state preserved…";
    case ProgressPhase::finalizing_restore:
      return "Finalizing restore…";
    case ProgressPhase::completed:
      return "Operation completed.";
  }
  return "Operation in progress…";
}

void show_status(const slint::ComponentHandle<AppWindow>& ui,
                 const fixer::LocalStatus& status) {
  std::string title;
  std::string detail = status.detail;
  switch (status.state) {
    case LocalState::missing:
      title = "Widevine is missing";
      detail = "Helium detected. Widevine is not installed in this folder.";
      break;
    case LocalState::locally_valid:
      title = "Widevine " + status.version;
      detail = "Local files are valid. Test playback in your browser.";
      break;
    case LocalState::locally_invalid:
      title = "Widevine files are invalid";
      break;
    case LocalState::recovery_required:
      title = "Restore required";
      break;
    case LocalState::unavailable:
      title = "Unable to check installation";
      break;
  }
  ui->set_status_title(slint::SharedString(title));
  ui->set_status_detail(slint::SharedString(detail));
  ui->set_status_valid(status.state == LocalState::locally_valid);
  ui->set_can_install(status.state == LocalState::missing ||
                      status.state == LocalState::locally_valid ||
                      status.state == LocalState::locally_invalid);
  // Restore itself validates ownership, journal and backup. A local check
  // cannot establish the presence of a usable backup for a completed
  // transaction.
  ui->set_can_restore(!status.target.empty());
  if (!status.target.empty())
    ui->set_target_path(slint::SharedString(fixer::utf8(status.target)));
}

enum class Job { inspect, install, restore };

int run_gui(bool smoke_test, const std::string& update_result = "") {
  auto ui = AppWindow::create();
  const slint::ComponentWeakHandle<AppWindow> weak(ui);
  std::jthread worker;
  int smoke_result = 1;
  int smoke_inspections = 0;
  bool startup_check = !smoke_test && update_result.empty() &&
                       !std::getenv("HELIUM_FIXER_DISABLE_UPDATE_CHECK");
  ui->set_app_version(FIXER_VERSION);
  ui->set_update_status(slint::SharedString(update_result));

  auto start = [&](Job job) {
    if (ui->get_busy()) return;
    if (worker.joinable()) worker.join();
    fixer::cancelled.store(false);
    fixer::Options options;
    options.target = fixer::from_utf8(std::string(ui->get_target_path()));
    options.restore = job == Job::restore;
    // Active operations always use the exact target shown and confirmed in the
    // UI, even if Helium updates after detection.
    if (job != Job::inspect && options.target.empty()) {
      ui->set_phase("Check the destination folder first.");
      return;
    }
    ui->set_busy(true);
    ui->set_inspecting(job == Job::inspect);
    if (job != Job::inspect) ui->set_status_valid(false);
    if (job != Job::inspect) ui->set_phase("Starting operation…");
    try {
      worker = std::jthread([weak, options, job, smoke_test, &smoke_result,
                             &smoke_inspections, &startup_check] {
        std::string message;
        try {
          if (job != Job::inspect) {
            fixer::execute_operation(
                options, [weak](const fixer::ProgressEvent& event) {
                  const std::string text = phase_text(event.phase);
                  slint::invoke_from_event_loop([weak, text] {
                    if (auto window = weak.lock())
                      (*window)->set_phase(slint::SharedString(text));
                  });
                });
            message = options.restore
                          ? "Previous state restored. You can start Helium."
                          : "Widevine installed. You can start Helium.";
          }
        } catch (const fixer::Error& error) {
          message = error.code == fixer::Code::cancelled
                        ? "Operation cancelled. Check the local status again."
                        : "Error: " + std::string(error.what());
        } catch (const std::exception& error) {
          message = "Error: " + std::string(error.what());
        }
        // Refresh after success or failure, including completed rollback. The
        // cancellation flag must not prevent this final read-only inspection.
        fixer::cancelled.store(false);
        fixer::LocalStatus status;
        try {
          status = fixer::inspect_local(options);
        } catch (const std::exception& error) {
          status.detail = error.what();
        }
        slint::invoke_from_event_loop([weak, status, message, smoke_test, job,
                                       &smoke_result, &smoke_inspections,
                                       &startup_check] {
          if (auto window = weak.lock()) {
            show_status(*window, status);
            (*window)->set_inspecting(false);
            (*window)->set_phase(slint::SharedString(message));
            (*window)->set_busy(false);
            if (startup_check) {
              startup_check = false;
              (*window)->invoke_check_app_update();
            }
            if (smoke_test && job == Job::inspect) {
              if (++smoke_inspections < 4) {
                (*window)->invoke_inspect();
                return;
              }
              bool passed =
                  status.state == LocalState::missing &&
                  !status.target.empty() &&
                  (*window)->get_status_title() == "Widevine is missing" &&
                  (*window)->get_can_install();
              (*window)->invoke_target_edited();
              passed = passed && !(*window)->get_can_install() &&
                       !(*window)->get_can_restore();
              (*window)->set_busy(true);
              (*window)->window().dispatch_close_requested_event();
              passed = passed && (*window)->window().is_visible();
              (*window)->invoke_cancel();
              passed = passed && fixer::cancelled.load();
              fixer::cancelled.store(false);
              (*window)->set_busy(false);
              smoke_result = passed ? 0 : 1;
              (*window)->window().hide();
            }
          }
        });
      });
    } catch (const std::exception& error) {
      ui->set_inspecting(false);
      ui->set_busy(false);
      ui->set_phase(slint::SharedString("Unable to start operation: " +
                                        std::string(error.what())));
    }
  };

  auto app_update = [&](bool install) {
    if (ui->get_busy()) return;
    if (worker.joinable()) worker.join();
    if (install && !ui->get_update_available()) return;
    const std::string expected = std::string(ui->get_update_version());
    ui->set_busy(true);
    ui->set_update_busy(true);
    ui->set_update_status(install ? "Downloading and verifying update…"
                                  : "Checking for updates…");
    fixer::cancelled.store(false);
    try {
      worker = std::jthread([weak, install, expected] {
        const auto check_started = std::chrono::steady_clock::now();
        std::string message;
        bool available = false, scheduled = false;
        std::string version;
        try {
          if (install) {
            fixer::require(fixer::app_self_update_supported(),
                           "Automatic updates are unavailable in this build");
            const auto target = fixer::app_executable_path();
            const auto hash =
                fixer::sha256(fixer::read_file(target, fixer::file_limit));
            const auto parent = fixer::app_update_jobs(target) / "packages";
            fixer::create_private_dir(parent);
            const auto prepared = fixer::prepare_app_update(parent);
            fixer::require(prepared.manifest.version == expected,
                           "The release changed. Check for updates again.");
            (void)fixer::start_app_update(prepared.directory, expected, hash);
            scheduled = true;
          } else {
            const auto status = fixer::check_app_update();
            version = status.available_version;
            switch (status.state) {
              case fixer::AppUpdateState::update_available:
                available = fixer::app_self_update_supported();
                message = available
                              ? "Update available"
                              : "Update available; download a supported build";
                break;
              case fixer::AppUpdateState::current:
                message = "Up to date";
                break;
              case fixer::AppUpdateState::installed_newer:
                message = "Newer than the stable release";
                break;
              case fixer::AppUpdateState::no_public_release:
                message = "No stable release yet";
                break;
              case fixer::AppUpdateState::no_compatible_package:
                message = "No signed GUI update published";
                break;
            }
          }
        } catch (const std::exception& error) {
          message = std::string(install ? "Update failed: "
                                        : "Update check failed: ") +
                    error.what();
        }
        // Keep quick metadata checks readable without delaying the UI thread.
        if (!install)
          std::this_thread::sleep_until(check_started + std::chrono::seconds(1));
        fixer::cancelled.store(false);
        slint::invoke_from_event_loop(
            [weak, message, version, available, scheduled] {
              if (auto window = weak.lock()) {
                (*window)->set_update_status(slint::SharedString(message));
                (*window)->set_update_version(slint::SharedString(version));
                (*window)->set_update_available(available);
                (*window)->set_update_busy(false);
                (*window)->set_busy(false);
                if (scheduled) (*window)->window().hide();
              }
            });
      });
    } catch (const std::exception& error) {
      ui->set_update_busy(false);
      ui->set_busy(false);
      ui->set_update_status(slint::SharedString(error.what()));
    }
  };
  ui->on_check_app_update([&] { app_update(false); });
  ui->on_update_app([&] { app_update(true); });

  ui->on_inspect([&] { start(Job::inspect); });
  ui->on_install([&] { start(Job::install); });
  ui->on_restore([&] { start(Job::restore); });
  ui->on_target_edited([&] {
    ui->set_status_valid(false);
    ui->set_can_install(false);
    ui->set_can_restore(false);
    ui->set_phase("Destination changed. Check it before making changes.");
  });
  ui->on_cancel([&] {
    fixer::cancelled.store(true);
    if (ui->get_update_busy())
      ui->set_update_status("Cancellation requested. Waiting for a safe stop.");
    else
      ui->set_phase(
          "Cancellation requested. Any ongoing recovery will finish safely.");
  });
  ui->window().on_close_requested([&] {
    if (ui->get_busy()) {
      ui->set_phase(
          "Cancel the operation and wait for it to finish before closing.");
      return slint::CloseRequestResponse::KeepWindowShown;
    }
    return slint::CloseRequestResponse::HideWindow;
  });
  slint::Timer::single_shot(std::chrono::milliseconds(0),
                            [&] { start(Job::inspect); });
  ui->run();
  fixer::cancelled.store(true);
  if (worker.joinable()) worker.join();
  return smoke_test ? smoke_result : 0;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    std::vector<std::string> arguments;
#ifdef _WIN32
    int count = 0;
    auto wide = CommandLineToArgvW(GetCommandLineW(), &count);
    fixer::require(wide != nullptr, "Cannot read GUI arguments");
    for (int i = 1; i < count; ++i)
      arguments.push_back(fixer::utf8(fixer::fs::path(wide[i])));
    LocalFree(wide);
    (void)argc;
    (void)argv;
#else
    for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);
#endif
    if (arguments.size() == 2 && arguments[0] == "--internal-app-update")
      return fixer::run_app_update_helper(fixer::from_utf8(arguments[1]));
    if (arguments.size() == 2 && arguments[0] == "--verify-app-release") {
      std::cout
          << fixer::inspect_app_release(fixer::from_utf8(arguments[1])).dump()
          << '\n';
      return 0;
    }
    if (arguments.size() == 2 && arguments[0] == "--app-update-result") {
      const auto result =
          fixer::app_update_job_status(fixer::from_utf8(arguments[1]));
      const auto state = result.at("state").get<std::string>();
      const auto text =
          state == "installed" ? "App updated successfully"
          : state == "restored"
              ? "Previous app version restored"
              : "App update failed: " + result.at("detail").get<std::string>();
      return run_gui(false, text);
    }
    if (arguments == std::vector<std::string>{"--restore-app"}) {
      (void)fixer::start_app_restore(fixer::app_executable_path());
      return 0;
    }
    if (arguments.size() == 2 && arguments[0] == "--restore-app") {
      (void)fixer::start_app_restore(fixer::from_utf8(arguments[1]));
      return 0;
    }
    const bool smoke_test =
        arguments == std::vector<std::string>{"--smoke-test"};
    fixer::require(arguments.empty() || smoke_test, "Unsupported GUI argument",
                   fixer::Code::invalid);
    return run_gui(smoke_test);
  } catch (const std::exception& error) {
    std::cerr << "GUI error: " << error.what() << '\n';
    return 1;
  }
}
