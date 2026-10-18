#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "app-window.h"
#include "fixer.hpp"

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

int run_gui(bool smoke_test) {
  auto ui = AppWindow::create();
  const slint::ComponentWeakHandle<AppWindow> weak(ui);
  std::jthread worker;
  int smoke_result = 1;
  int smoke_inspections = 0;
  ui->set_app_version(FIXER_VERSION);

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
    ui->set_status_valid(false);
    ui->set_phase(job == Job::inspect ? "Reading local status…"
                                      : "Starting operation…");
    try {
      worker = std::jthread([weak, options, job, smoke_test, &smoke_result,
                             &smoke_inspections] {
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
                                       &smoke_result, &smoke_inspections] {
          if (auto window = weak.lock()) {
            show_status(*window, status);
            (*window)->set_phase(slint::SharedString(message));
            (*window)->set_busy(false);
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
      ui->set_busy(false);
      ui->set_phase(slint::SharedString("Unable to start operation: " +
                                        std::string(error.what())));
    }
  };

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
    const bool smoke_test = argc == 2 && std::string(argv[1]) == "--smoke-test";
    fixer::require(argc == 1 || smoke_test, "Unsupported GUI argument",
                   fixer::Code::invalid);
    return run_gui(smoke_test);
  } catch (const std::exception& error) {
    std::cerr << "GUI error: " << error.what() << '\n';
    return 1;
  }
}
