# Slint-Oberfläche (erste Vorschau)

Die optionale Oberfläche verwendet Slint 1.18.1 und den vorhandenen C++-Kern.
Sie bietet lokalen Status, einen expliziten Widevine-Zielpfad, Installation von
Google, Wiederherstellung, Phasenmeldungen und Abbruch. Installation und Restore
verlangen eine Bestätigung. Beim Start findet nur eine lokale Prüfung statt.
Laufende Arbeiten blockieren das Fenster nicht; ein Schließen während eines
Vorgangs wird verhindert, bis der Vorgang bzw. seine sichere Rücknahme beendet ist.

Der Schalter `FIXER_BUILD_GUI` ist standardmäßig aus. Die CLI und deren signierte
Release-Pakete bleiben eigenständig. GUI-App-Updates, Linux-Praxistest und die
vollständige Prüfung der zusätzlichen Lizenzhinweise folgen vor ihrer Auslieferung.
Die Versionsanzeige ist noch kein automatischer Update-Check.

## Windows in dieser Arbeitskopie

Rust ist lokal unter `build/ui-tools` abgelegt. Es verändert die globale
PATH-Einstellung nicht. CLions MinGW, Ninja und CMake werden verwendet.

```powershell
.\tools\build_gui.ps1 -Test
.\build\gui\helium_drm_fixer_gui.exe
```

Das Skript stellt seine temporären Umgebungsänderungen danach zurück. Der erste
Build lädt Rust-Abhängigkeiten und benötigt deutlich mehr Platz als die fertige
EXE. Weitere Builds verwenden denselben Cache und denselben Build-Ordner.

Andere Entwickler benötigen Rust ab 1.92, eine zum C++-Compiler passende Rust-
Toolchain sowie CMake ab 3.24. Der Helfer ist auf CLions Standardinstallation unter
`%LOCALAPPDATA%/Programs/CLion` ausgelegt. Bei anderer Installation CMake direkt
oder ein entsprechendes CLion-Profil verwenden. Für MinGW wird das Rust-Ziel
`x86_64-pc-windows-gnu` benötigt, für MSVC `x86_64-pc-windows-msvc`.

## Linux und allgemeiner CMake-Aufruf

```sh
cmake -S . -B build/gui -G Ninja -DCMAKE_BUILD_TYPE=Release -DFIXER_BUILD_GUI=ON -DBUILD_TESTING=ON
cmake --build build/gui --target helium_drm_fixer_gui --parallel 4
ctest --test-dir build/gui -R '^gui_readonly_startup$' --output-on-failure
./build/gui/helium_drm_fixer_gui
```

Zusätzlich zu den bisherigen Linux-Abhängigkeiten werden Rust und die zum
Slint-Winit-Backend gehörenden X11-/Wayland-Entwicklungspakete benötigt. Der
Fenstertest benötigt eine grafische Sitzung, in CI beispielsweise Xvfb.

## Aufbau und Portabilität

- `app-window.slint`: Layout, Hell-/Dunkelmodus und Bestätigung vor Änderungen.
- `main.cpp`: Hintergrundarbeit, Fortschrittsübermittlung an den UI-Thread und
  Anbindung von `inspect_local` / `execute_operation`.
- `../cmake/SlintGui.cmake`: festgelegte Quellarchive mit SHA-256, statische
  Slint-Laufzeit und eingebettete UI-Ressourcen. Keine Git-Downloads.
- `../tests/gui_smoke.py`: echte Fensterinitialisierung und asynchrone lokale
  Prüfung mit isoliertem Profil; keine Widevine-Installation. Unter Windows
  wird die EXE ohne Nachbar-DLLs und nur mit System32 im PATH gestartet.
  Außerdem werden die Sperre nach einer Zieländerung, der Schließschutz bei
  laufender Arbeit und das Abbruchsignal geprüft.
  Unter Windows betätigt `gui_interaction.ps1` die echten Schaltflächen über
  UI Automation: wiederholtes Prüfen, Installationsbestätigung mit Zurück sowie
  Restore ohne Backup. Die vollständige Testverzeichnis-Prüfung bleibt aktiv.

Die Windows-GUI wird statisch gelinkt. Die verbleibenden Windows-System-DLLs
werden vom Betriebssystem bereitgestellt. Eine erfolgreiche lokale Prüfung ist
noch kein Nachweis für alle Windows-11-Systeme; ein Test auf sauberem Windows
bleibt vor der Freigabe erforderlich. Linux nutzt weiterhin Systembibliotheken.

Die statische MinGW-GUI verwendet explizit UCRT (`-mcrtdll=ucrt`). Gemischte
MSVCRT-/UCRT-Allocatorimporte führten beim Join beendeter Arbeitsthreads zu
Heap-Beschädigung. Der Windows-Test lehnt einen direkten MSVCRT-Import deshalb
ab und prüft zusätzlich echte Button-Interaktionen nach dem Fensterstart.

Slint 1.18.1 versieht unter Windows einige statische Vtable-Zugriffe mit
DLL-Import-Markierungen. `slint-static.hpp` korrigiert diese Markierung nur für
die beiden GUI-Übersetzungseinheiten; Slint-Quellen werden nicht verändert.

Slint wird für diese Desktop-App unter der Slint Royalty-free Desktop, Mobile,
and Web Applications License 2.0 verwendet. Das vorgeschriebene `AboutSlint`-
Widget ist über das zentrale Settings-Menü unter „Settings → About“ erreichbar.
Die Oberfläche ist englisch, die Theme-Auswahl liegt unter „Settings → Color theme“.
Help und About ersetzen den früheren Menüleisten- und Footer-Bereich. Lizenztext:
https://github.com/slint-ui/slint/blob/v1.18.1/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md
