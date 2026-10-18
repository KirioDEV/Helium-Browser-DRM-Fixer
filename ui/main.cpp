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
      return "Zielordner geprüft.";
    case ProgressPhase::checking_source:
      return "Installationsquelle prüfen …";
    case ProgressPhase::querying_release:
      return "Widevine-Version bei Google abfragen …";
    case ProgressPhase::checking_cache:
      return "Vorhandenes Paket erneut prüfen …";
    case ProgressPhase::downloading_package:
      return "Widevine herunterladen und verifizieren …";
    case ProgressPhase::trusting_local_source:
      return "Lokale Quelle ausgewählt.";
    case ProgressPhase::source_ready:
      return "Quelle geprüft.";
    case ProgressPhase::preparing:
      return "Dateien vorbereiten …";
    case ProgressPhase::preserving_previous:
      return "Bisherigen Zustand sichern …";
    case ProgressPhase::installing:
      return "Widevine installieren …";
    case ProgressPhase::verifying_installation:
      return "Installierte Dateien prüfen …";
    case ProgressPhase::restoring:
      return "Vorherigen Zustand wiederherstellen …";
    case ProgressPhase::restore_validated:
      return "Wiederherstellung geprüft …";
    case ProgressPhase::restore_current_preserved:
      return "Aktuellen Zustand gesichert …";
    case ProgressPhase::finalizing_restore:
      return "Wiederherstellung abschließen …";
    case ProgressPhase::completed:
      return "Vorgang abgeschlossen.";
  }
  return "Vorgang läuft …";
}

void show_status(const slint::ComponentHandle<AppWindow>& ui,
                 const fixer::LocalStatus& status) {
  std::string title;
  std::string detail = status.detail;
  switch (status.state) {
    case LocalState::missing:
      title = "Widevine fehlt";
      detail =
          "Helium wurde gefunden. Widevine ist in diesem Zielordner noch nicht "
          "installiert.";
      break;
    case LocalState::locally_valid:
      title = "Widevine " + status.version;
      detail =
          "Manifest und Bibliothek sind lokal gültig. Die Wiedergabe lässt "
          "sich im Browser testen.";
      break;
    case LocalState::locally_invalid:
      title = "Widevine lokal ungültig";
      break;
    case LocalState::recovery_required:
      title = "Wiederherstellung erforderlich";
      break;
    case LocalState::unavailable:
      title = "Prüfung nicht möglich";
      break;
  }
  ui->set_status_title(slint::SharedString(title));
  ui->set_status_detail(slint::SharedString(detail));
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
      ui->set_phase("Bitte zuerst den Zielordner prüfen.");
      return;
    }
    ui->set_busy(true);
    ui->set_phase(job == Job::inspect ? "Lokalen Status lesen …"
                                      : "Vorgang starten …");
    try {
      worker = std::jthread([weak, options, job, smoke_test, &smoke_result] {
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
            message =
                options.restore
                    ? "Vorheriger Zustand wiederhergestellt. Helium kann "
                      "gestartet werden."
                    : "Widevine installiert. Helium kann gestartet werden.";
          }
        } catch (const fixer::Error& error) {
          message = error.code == fixer::Code::cancelled
                        ? "Vorgang abgebrochen. Lokalen Status erneut prüfen."
                        : "Fehler: " + std::string(error.what());
        } catch (const std::exception& error) {
          message = "Fehler: " + std::string(error.what());
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
                                       &smoke_result] {
          if (auto window = weak.lock()) {
            show_status(*window, status);
            (*window)->set_phase(slint::SharedString(message));
            (*window)->set_busy(false);
            if (smoke_test && job == Job::inspect) {
              bool passed = status.state == LocalState::missing &&
                            !status.target.empty() &&
                            (*window)->get_status_title() == "Widevine fehlt" &&
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
      ui->set_phase(
          slint::SharedString("Vorgang konnte nicht gestartet werden: " +
                              std::string(error.what())));
    }
  };

  ui->on_inspect([&] { start(Job::inspect); });
  ui->on_install([&] { start(Job::install); });
  ui->on_restore([&] { start(Job::restore); });
  ui->on_target_edited([&] {
    ui->set_can_install(false);
    ui->set_can_restore(false);
    ui->set_phase("Ziel geändert. Bitte vor einer Änderung erneut prüfen.");
  });
  ui->on_cancel([&] {
    fixer::cancelled.store(true);
    ui->set_phase(
        "Abbruch angefordert. Eine laufende Wiederherstellung wird sicher "
        "abgeschlossen.");
  });
  ui->window().on_close_requested([&] {
    if (ui->get_busy()) {
      ui->set_phase(
          "Bitte zuerst abbrechen und das Ende des Vorgangs abwarten.");
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
