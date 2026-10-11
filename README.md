# Helium DRM Fixer (C++20)

Konsolenprogramm für Windows 11 x64 und native Linux-x86_64-Installationen.
Es beschafft Widevine aus dem Google-Komponentenupdate, prüft SHA-256 und
CRX3-Signaturen und installiert das CDM mit Backup und Wiederherstellung.
Ein unabhängiges Drittanbieterprojekt, keine offizielle Helium-Komponente.

## Bauen in CLion unter Windows

Dieses Verzeichnis als CMake-Projekt öffnen. C++20 ist bereits eingestellt.
CLions mitgeliefertes MinGW funktioniert; CMake benötigt mindestens Version 3.24.
Beim ersten Konfigurieren lädt CMake zwei per Version und SHA-256 festgelegte
Quellarchive herunter: nlohmann/json 3.12.0 und miniz 3.1.2. Es verwendet kein Git.
Bei bereits vorhandenen `.deps`-Archiven wird deren Hash ebenfalls geprüft.

In CLion das Ziel `helium_drm_fixer` auswählen und bauen. Zum ersten Start
`--help` oder `--check` als Programmargument setzen: ein Start ohne Argumente
beginnt die Installation, wenn Helium erkannt und geschlossen ist.

Mit MinGW liegen die benötigten drei Compiler-Laufzeit-DLLs neben der EXE.
Diese Dateien beim Weitergeben zusammenlassen. Windows-HTTP, TLS und
Kryptografie verwenden WinHTTP und CNG aus dem Betriebssystem.
MSVC wird ebenfalls in der CI-Konfiguration berücksichtigt; ein lokaler
MSVC-Lauf ist in dieser Umgebung noch nicht erfolgt.

## Bauen unter Linux

Getestete Build-Basis: Ubuntu 24.04 x86_64, GCC 13 und Clang 18.
Benötigt werden CMake >= 3.24, ein C++20-Compiler, Ninja, libcurl >= 7.85,
OpenSSL >= 3.0 und System-CA-Zertifikate. Python ist nur für zusätzliche Tests nötig.

```sh
sudo apt install build-essential cmake ninja-build libcurl4-openssl-dev libssl-dev ca-certificates python3
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Das Programm selbst im Benutzerkonto starten, ohne sudo. Andere Distributionen
müssen passende Bibliotheken bereitstellen. Keine allgemeine Kompatibilitätszusage
für alle Linux-Systeme. Flatpak und Snap werden nicht unterstützt; AppImage ist
noch nicht separat mit einem Browser getestet.

## Verwendung

Windows:

```powershell
.\helium_drm_fixer.exe --help
.\helium_drm_fixer.exe --check
.\helium_drm_fixer.exe --dry-run
```

Linux:

```sh
./helium_drm_fixer --check
./helium_drm_fixer --dry-run
```

`--check` und `--dry-run` sind lokal und schreibfrei: keine Downloads, keine
Cache-Erzeugung und keine Protokolldateien. Eine unbekannte Online-Version wird
nicht geraten. Ein lokal plausibles CDM beweist weder dessen Herausgeberintegrität
noch funktionierendes Streaming.

Für die tatsächliche Installation Helium vollständig schließen und das Programm
ohne Prüfmodus starten. Der Standard ist `--source google`; bei Fehlern findet
kein stiller Wechsel auf eine andere Vertrauensquelle statt.

`--helium-path` bezeichnet immer den **exakten WidevineCdm-Ordner**, nicht den
Helium-Anwendungsordner. Beispiel unter Windows:

```powershell
.\helium_drm_fixer.exe --dry-run --helium-path "C:\Users\NAME\AppData\Local\imput\Helium\Application\VERSION\WidevineCdm"
```

Linux nutzt `<Profil>/WidevineCdm/<CDM-Version>` und die JSON-Hint-Datei innerhalb
des WidevineCdm-Roots. `XDG_CONFIG_HOME` wird berücksichtigt; bei mehreren
erkannten Profilen ist ein expliziter Zielpfad erforderlich.

Weitere Quellen werden ausdrücklich gewählt:

```sh
./helium_drm_fixer --source chrome --chrome-path /opt/google/chrome/WidevineCdm
./helium_drm_fixer --source package --package /path/to/widevine.crx3
```

Chrome-Dateien werden als lokal vertraute Quelle behandelt, nicht als
signaturgeprüftes Google-Paket ausgegeben. Offline-CRX3-Pakete müssen dieselbe
Widevine-Identität und gültige Signaturen haben; ohne Online-Metadaten ist dabei
keine Aussage zur Aktualität möglich.

## Backup und Recovery

Neben dem Ziel entsteht ein privates Verzeichnis `.helium-drm-fixer`.
Es enthält ein Eigentumskennzeichen, eine Sperre, das Transaktionsjournal sowie
Backups. Vorhandene CDM-Dateien werden umbenannt, nicht vorab gelöscht.
Unter Linux ist die Hint-Datei Teil des gemeinsam gesicherten CDM-Ordners.

```sh
./helium_drm_fixer --restore
```

Mit einem individuellen Zielpfad denselben `--helium-path` auch beim Restore
angeben. Nach einem Abbruch verweigert eine neue Installation den Start, bis die
Wiederherstellung abgeschlossen ist. Hat sich der Inhalt des Backups oder der
aktuellen Installation verändert, erfolgt keine automatische Überschreibung.

Die letzte Transaktion ist über `--restore` erreichbar. Frühere Journale und
Backups bleiben zur manuellen Wiederherstellung erhalten. Es gibt bewusst keine
automatische Backup-Löschung; sie können Speicherplatz belegen.

Exitcodes: 0 Erfolg/lokal plausibel, 1 Betriebsfehler, 2 ungültige Optionen,
3 fehlt/nicht gefunden, 4 Sicherheitsprüfung fehlgeschlagen,
5 Recovery erforderlich, 130 Abbruch.

## Prüfung und Auslieferung

Der C++-Code verwendet das Google-Format aus der projektweiten
`.clang-format`. In CLion unter **Settings → Editor → Code Style → C/C++**
die Unterstützung für ClangFormat aktivieren. Zum Formatieren und Prüfen
mit `clang-format` im PATH:

```sh
clang-format -i main.cpp include/fixer.hpp src/*.cpp tests/*.cpp
clang-format --dry-run --Werror main.cpp include/fixer.hpp src/*.cpp tests/*.cpp
```

Die Tests verwenden künstliche CDM-Dateien in temporären Verzeichnissen.
Sie laden keine Bibliothek in einen Prozess und verändern keine reale
Helium-Installation. Zusätzlich werden Prozessabbrüche an fünf
Transaktionsgrenzen getestet. Der Clang-Fuzz-Harness prüft die Parser mit
AddressSanitizer/UndefinedBehaviorSanitizer.

```sh
cmake --preset release
cmake --build --preset release
cmake --install build/release --prefix build/package
```

Die CI-Datei baut Windows mit MSVC und Linux mit GCC/Clang und stellt
Build-Artefakte bereit. Sie veröffentlicht keine Releases.
Details zu Sicherheitsgrenzen und noch ausstehenden Browser-Tests stehen in
[SECURITY.md](SECURITY.md). Bibliotheksquellen und Lizenzhinweise stehen in
[THIRD_PARTY.md](THIRD_PARTY.md). Widevine selbst wird nicht mitgeliefert.
