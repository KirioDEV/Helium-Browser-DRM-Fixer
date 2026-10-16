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
Das Ziel-Dateisystem muss `renameat2` mit `RENAME_NOREPLACE` unterstützen;
ohne diese Funktion wird eine Installation abgebrochen. Für die geprüften
Elternverzeichnisse werden Leserechte benötigt.

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

Der Installationslauf meldet Quellenprüfung, Vorbereitung, Erhalt des bisherigen
Bestands, Installation und lokale Nachprüfung. Bei einer Chrome-Quelle erscheint
auch ohne `--verbose` der Hinweis, dass ihre Herausgeberintegrität nicht geprüft
wird. Erfolg wird erst nach der abschließenden lokalen Prüfung gemeldet.

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

Wird während Installation oder Restore ein Eltern- oder Verwaltungsordner
verschoben bzw. ersetzt, wird abgebrochen. Vor einem weiteren Restore zuerst
die ursprüngliche Pfadzuordnung klären. Fremde Ersatzordner werden nicht
automatisch zurückverschoben oder überschrieben.

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
clang-format -i main.cpp include/*.hpp src/*.cpp tests/*.hpp tests/*.cpp
clang-format --dry-run --Werror main.cpp include/*.hpp src/*.cpp tests/*.hpp tests/*.cpp
```

Die Tests verwenden künstliche CDM-Dateien in temporären Verzeichnissen.
Sie laden keine Bibliothek in einen Prozess und verändern keine reale
Helium-Installation. Zusätzlich werden Prozessabbrüche an fünf
Transaktionsgrenzen getestet. Der Clang-Fuzz-Harness prüft die Parser mit
AddressSanitizer/UndefinedBehaviorSanitizer.

Für die lokalen HTTPS-Integrationstests werden zusätzlich Python und das
OpenSSL-Kommando benötigt; unter Windows wird auch Git for Windows als
Installationsort von OpenSSL berücksichtigt. Die Tests prüfen Zertifikatsfehler,
Weiterleitungen, Antwortgrößen, abgeschnittene Antworten, Zeitlimits und Abbruch.
Hinzu kommen kontrolliert eingespeiste DNS-Fehler und Antwortmengen: gemischte
öffentliche/private Adressen werden vollständig abgelehnt, und jeder Redirect
wird erneut geprüft. Die nativen Transporte verbinden sich mit einer festgelegten
IP; TLS-SNI, Zertifikatsprüfung und HTTP-Host behalten den ursprünglichen Hostnamen.
Die Fixture prüft diese Trennung ausdrücklich auch mit einem nur für die IP
gültigen Zertifikat. DNS-Antworten sind hierbei simuliert; der System-Resolver
wird nicht umkonfiguriert.

Die DNS-Vorabfrage wartet höchstens zehn Sekunden und zählt zum gemeinsamen
120-Sekunden-Anfragebudget. Ein Abbruch wird auch während einer blockierten
Namensauflösung verarbeitet. Ein einzelner Worker kapselt den System-Resolver:
Eine vom Betriebssystem noch nicht beendete Auflösung kann im Hintergrund
weiterlaufen, startet aber keine Verbindung. Bis sie zurückkehrt, werden weitere
Auflösungsversuche mit einer Fehlermeldung abgelehnt; es werden keine weiteren
Worker oder Warteschlangen angelegt.

`tests/dns_blackhole.py` prüft zusätzlich den echten Linux-System-Resolver mit
der normalen CLI. Das Skript benötigt einen isolierten Container mit
`--network none --dns 127.0.0.1` und Berechtigung zum Binden an UDP-Port 53.
Es beantwortet DNS-Anfragen absichtlich nicht und prüft Zeitlimit, SIGINT-Abbruch
und Programmende, ohne Resolver-Einstellungen selbst zu ändern. Dieser separate
Container-Test gehört nicht zum normalen CTest-Lauf.

`tests/dns_rebinding.py` prüft sieben weitere Fälle pro Linux-Compiler mit einem
echten DNS-Server und dem System-Resolver: IP-Pinning trotz Rebinding, erneute
Prüfung bei Redirects, zulässiger Wechsel auf eine andere öffentliche IP,
gemischte öffentliche/private IPv4-/IPv6-Antworten, private Antwort und NXDOMAIN.
Ein separater Container benötigt dafür
`--network none --dns 127.0.0.1 --cap-add NET_ADMIN`. Das Skript verlangt Docker
mit ausschließlich dem Loopback-Interface und fügt nur dort zwei öffentliche
Test-IP-Adressen hinzu. Es verwendet den getrennten `fixer_network_tests`-Build
und eine private CA-Datei; der normale Build erhält keine Testkonfiguration.
TLS-SNI und HTTP-Host bleiben beim erlaubten Hostnamen, und der private
Rebinding-Zielserver darf keinen Kontakt erhalten. DNS-Einstellungen und
Zertifikatsspeicher des Hosts werden nicht geändert. Auch dieser Test läuft
separat von CTest; im Container wird er mit den Testprogrammen aufgerufen:

```sh
python3 /source/tests/dns_rebinding.py /build/gcc/fixer_network_tests /build/clang/fixer_network_tests
```

Es werden keine Test-Zertifikate in den System-Vertrauensspeicher importiert.
Die dafür separat gebaute `fixer_network_tests`-Datei wird nicht mit installiert.
Die normale EXE enthält keine Loopback- oder Test-Zertifikatskonfiguration.

Mit `-DFIXER_REQUIRE_NETWORK_TESTS=ON` schlägt die CMake-Konfiguration fehl,
wenn diese Testvoraussetzungen fehlen. CI und Docker-Testskript verlangen diese
Prüfungen; beim normalen lokalen Build werden fehlende Voraussetzungen gemeldet.

Die Fehlerfalltests prüfen außerdem Abbruch mit Rollback, manipulierte Backups
und Journale, Hardlinks sowie unter Windows gesperrte DLLs. Ein zusätzlicher
CTest-Lauf führt 26 Szenarien mit der tatsächlichen Programmdatei aus:
Installation, Update, Restore, Crash-Recovery, Exitcodes und Unicode-Pfade.
Er verwendet ausschließlich synthetische PE-/ELF-Header in separaten temporären
Profilen; die Dateien werden nicht als Bibliotheken geladen. Quell-, Ziel-,
Home- und Cachepfade sind isoliert. Eine laufende Helium-Instanz blockiert auch
diesen Test; es gibt keinen Test-Bypass der Prozessprüfung. Dateisystem-Snapshots
prüfen verbleibende Inhalte und Änderungszeiten der schreibfreien und abgelehnten
Aufrufe. Sie erfassen keine zwischenzeitlichen Schreib-/Lösch-Systemaufrufe und
belegen allein keine Netzwerkfreiheit.

Für Linux gibt es
drei zusätzliche Testmodi:

```sh
# Als normaler Benutzer, nicht als root:
./build/debug/fixer_tests --permission-denied
# Nur auf einem eigenen Test-Dateisystem mit höchstens 64 KiB freiem Platz:
./build/debug/fixer_tests --low-space /pfad/zum/test-dateisystem
# Nur auf einem leeren, separaten tmpfs (2-16 MiB, empfohlen 8 MiB):
./build/debug/fixer_tests --transaction-space /pfad/zum/leeren/test-tmpfs
```

Die Transaktionstests füllen dieses tmpfs gezielt. Sie prüfen 18 Fälle für
Erstinstallation, Update und Wiederherstellung einschließlich teilweise
geschriebener Staging-Dateien und fortsetzbarer Recovery nach Freigabe des
Speicherplatzes. Die Linux-CI richtet dafür ein eigenes 8-MiB-tmpfs ein.
Im Docker-Testskript aktiviert `FIXER_SPACE_TEST_ROOT` diese Fälle für beide
Compiler; der Pfad muss auf ein entsprechend eingebundenes Test-tmpfs zeigen.

Das Docker-Testskript `tools/run_linux_tests.sh` fuzztestet standardmäßig
60 Sekunden. `FIXER_FUZZ_SECONDS` erlaubt 1 bis 3600 Sekunden; ein längerer
Lauf ersetzt keine umfassende Sicherheitsprüfung.

```sh
cmake --preset release
cmake --build --preset release
cmake --install build/release --prefix build/package
```

Die CI-Datei baut Windows mit MSVC und Linux mit GCC/Clang und stellt
Build-Artefakte bereit. Sie veröffentlicht keine Releases.
README und Projekt-/Bibliothekslizenzen sind Pflichtbestandteile der Pakete.
Die lokal ignorierten Dateien `SECURITY.md` und `THIRD_PARTY.md` werden zusätzlich
mitinstalliert, wenn sie vorhanden sind; ein frischer CI-Checkout benötigt sie nicht.
Details zu Sicherheitsgrenzen und noch ausstehenden Browser-Tests stehen in
[SECURITY.md](SECURITY.md). Bibliotheksquellen und Lizenzhinweise stehen in
[THIRD_PARTY.md](THIRD_PARTY.md). Widevine selbst wird nicht mitgeliefert.
