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

Die fertige Windows-Ausgabe wird mit MSVC und statisch eingebundener C++-Laufzeit
gebaut: **eine startbare EXE ohne zusätzliche mitzuliefernde DLLs**. Projekt-
und Bibliothekslizenzen sind als Ressourcen in der EXE enthalten. Windows-HTTP,
TLS und Kryptografie verwenden WinHTTP und CNG aus dem Betriebssystem.
Die CI bietet dafür das eigene Artefakt `windows-x64-standalone-exe` an.
GitHub-Actions-Artefakte werden als ZIP heruntergeladen; darin liegt nur die EXE.
Eine spätere Veröffentlichung kann diese EXE direkt als Release-Download anbieten.

CLions mitgelieferter MinGW-Entwicklungsbuild benötigt weiterhin die drei
Compiler-Laufzeit-DLLs neben seiner EXE. Diese Toolchain lässt sich hier nicht
sauber mit allen statischen Laufzeitbibliotheken verbinden; für die einzelne
auszuliefernde EXE den MSVC-Release-Build verwenden. Ein lokaler MSVC-Lauf ist
in dieser Umgebung noch nicht erfolgt. Die CI prüft dessen DLL-Importe und
startet die EXE allein aus einem temporären Ordner mit bereinigtem Suchpfad.

Bei der späteren GUI muss die Auswahl und Einbindung der GUI-Bibliothek dieses
Ziel weiterhin berücksichtigen. Die aktuelle EXE ist noch das Konsolenprogramm.

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

`--check --json` gibt den lokalen Status als einzelnes JSON-Objekt aus, auch mit
`--verbose`. Die Zustände unterscheiden fehlendes, lokal ungültiges und lokal
plausibles Widevine, offene Recovery sowie eine nicht mögliche Prüfung.
Lesefehler und beschädigte Verwaltungsjournale sind keine automatische
Reparaturempfehlung. Die Exitcodes bleiben erhalten; `--json` unterstützt den
lokalen `--check` und den separaten Online-Befehl `--check-app-update`.
Lesefehler verwenden den Betriebsfehler-Code 1 und werden
nicht mehr pauschal als ungültiger CDM-Inhalt mit Code 4 ausgegeben.

JSON-Schema 1 enthält `state` (`missing`, `locally_invalid`, `locally_valid`,
`recovery_required` oder `unavailable`), `target`, `version`, `detail` und
`exit_code`. Ein nicht auflösbares Ziel und eine nicht festgestellte Version sind
`null`. `online_version_checked`, `publisher_integrity_verified` und
`streaming_compatibility_verified` sind jeweils `false`. Optionsfehler und
Abbruch nutzen den normalen Fehlerpfad. Der C++-Kern liefert dasselbe Ergebnis
über `inspect_local(const Options&)` als `LocalStatus` ohne Konsolenausgabe.

Für die tatsächliche Installation Helium vollständig schließen und das Programm
ohne Prüfmodus starten. Der Standard ist `--source google`; bei Fehlern findet
kein stiller Wechsel auf eine andere Vertrauensquelle statt.

Der Installationslauf meldet Quellenprüfung, Vorbereitung, Erhalt des bisherigen
Bestands, Installation und lokale Nachprüfung. Bei einer Chrome-Quelle erscheint
auch ohne `--verbose` der Hinweis, dass ihre Herausgeberintegrität nicht geprüft
wird. Erfolg wird erst nach der abschließenden lokalen Prüfung gemeldet.

Der C++-Kern stellt aktive Vorgänge über
`execute_operation(const Options&, const ProgressObserver&)` bereit. Er liefert
typisierte Phasenereignisse für Quellenprüfung, Google-Abfrage/Cache/Download,
Vorbereitung, Installation, Nachprüfung und Restore sowie ein `OperationResult`.
Die CLI erzeugt daraus ihre Textmeldungen; der aktive Kern schreibt selbst nicht
auf stdout/stderr. Check-, Plan- und Hilfemodi werden von dieser aktiven API
abgelehnt. Auch direkte C++-Aufrufer durchlaufen die Optionsvalidierung.

Callbacks laufen synchron im ausführenden Thread. Eine spätere UI muss Ereignisse
kopieren und an ihren UI-Thread weiterreichen; Callbacks müssen kurz bleiben und
dürfen keine verschachtelten Operationen starten. Callback-Ausnahmen werden
abgefangen, damit eine Anzeige keinen Rollback auslöst oder einen bereits
gespeicherten Erfolg in einen Fehler umwandelt. Abbruch erfolgt weiterhin über
das gemeinsame Abbruchsignal. Nach Beginn der kritischen Wiederherstellung wird
diese sicher zu Ende geführt; ein erst nach dem Commit eintreffender Abbruch
macht die abgeschlossene Installation nicht rückwirkend erfolglos.
`completed` wird ausschließlich nach erfolgreichem Abschluss ausgegeben.
Die Ereignisse sind Phasenmeldungen; sie liefern keine Prozent- oder Bytezähler.
Versionsangaben in Download-/Cachephasen stammen zunächst aus Update-Metadaten.
Erst `source_ready` folgt auf die jeweilige Quellenprüfung; lokale Chrome-Dateien
bleiben dabei ausdrücklich ohne nachgewiesene Herausgeberintegrität.

`--helium-path` bezeichnet immer den **exakten WidevineCdm-Ordner**, nicht den
Helium-Anwendungsordner. Beispiel unter Windows:

```powershell
.\helium_drm_fixer.exe --dry-run --helium-path "C:\Users\NAME\AppData\Local\imput\Helium\Application\VERSION\WidevineCdm"
```

Linux nutzt `<Profil>/WidevineCdm/<CDM-Version>` und die JSON-Hint-Datei innerhalb
des WidevineCdm-Roots. `XDG_CONFIG_HOME` wird berücksichtigt; bei mehreren
erkannten Profilen ist ein expliziter Zielpfad erforderlich.

Unter Windows kann alternativ `--helium-app-path` einen Helium-Anwendungsordner
oder einen konkreten Versionsordner bezeichnen:

```powershell
.\helium_drm_fixer.exe --dry-run --helium-app-path "C:\Users\NAME\AppData\Local\imput\Helium\Application"
```

Der Anwendungsordner wird bei jedem Aufruf erneut aufgelöst: Die höchste gültige
vierstellige Versionsnummer wird numerisch gewählt. Ungültige x64-EXE-Header,
Reparse Points, Hardlinks und numerisch gleichnamige Versionsordner werden
abgelehnt. Die höchste installierte Version ist kein Nachweis der gerade
laufenden Browserversion. Helium muss vor einer Installation geschlossen sein.

Die automatische Windows-Erkennung bevorzugt die zwei LocalAppData-Pfade
`imput/Helium/Application` und `Helium/Application`, danach die
`Helium/Application`-Ordner unter Program Files und Program Files (x86).
Bei fehlendem `LOCALAPPDATA` wird das absolute `USERPROFILE/AppData/Local`
auch für den Cache verwendet. Fremde Benutzerprofile werden nicht durchsucht.
Die Erkennung erteilt keine Schreibrechte auf systemweite Installationen.

`--helium-app-path` ist Windows-spezifisch und darf weder mit `--helium-path`
noch mit `--restore` kombiniert werden. Für Restore den **exakten bisherigen
WidevineCdm-Root** mit `--helium-path` angeben: Nach einem Browserupdate könnte
der Anwendungsordner bereits auf eine andere Version zeigen. Linux verwendet
weiterhin den profilbezogenen WidevineCdm-Root.

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

Die Fixer-App kann veröffentlichte Versionen ihres eigenen Forks prüfen:

```sh
helium_drm_fixer --check-app-update
helium_drm_fixer --check-app-update --json
```

Die feste Quelle ist
[`KirioDEV/Helium-Browser-DRM-Fixer`](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer).
Dieser Befehl fragt ausschließlich Release-Metadaten ab, benötigt kein Helium
und erzeugt weder einen Paketdownload noch einen App-Cache. Die Anfrage hat ein
Gesamtzeitlimit von 15 Sekunden und folgt keinen Weiterleitungen. TLS-, DNS-
und IP-Prüfungen werden mit den bestehenden nativen Transporten ausgeführt;
GitHub wird dadurch nicht als Widevine-Quelle zugelassen. Der Online-Befehl
ist mit CDM-Ziel-, Installations-, Prüf- und Restore-Optionen nicht kombinierbar.

App-Versionen verwenden drei kanonische numerische Komponenten (`1.10.0`),
Release-Tags optional ein vorangestelltes `v`. Entwürfe, Vorabversionen und
mehrdeutige/ungültige Versionsangaben werden abgelehnt. Vierstellige
Widevine-Versionen verwenden weiterhin ihre eigene Prüfung.
Ein neueres Release benötigt für den Zustand `update_available` ein fertig
hochgeladenes Paket mit passendem Namen, URL und plausibler Größe:

| Plattform | Vorgesehenes C++-Releasepaket |
| --- | --- |
| Windows 11 x64 | `helium-drm-fixer-cpp-VERSION-windows-x64.zip` |
| Linux x86_64 / Ubuntu 24.04 | `helium-drm-fixer-cpp-VERSION-linux-x86_64-ubuntu24.04.zip` |

Go-Releases oder Releases ohne dieses plattformspezifische Paket werden nicht
als kompatibles Update angeboten. Die CI erzeugt zusätzlich unsignierte ZIP-
Kandidaten mit Manifest als eigene Artefakte; sie veröffentlicht keine Releases.
Eine Versionsabfrage ist **keine Paket- oder Signaturprüfung**.
JSON-Schema 1 liefert `repository`, `installed_version`, `available_version`,
`release_url`, `package_name`, `exit_code` und einen der Zustände
`update_available`, `current`, `installed_newer`, `no_public_release` oder
`no_compatible_package`. `package_verified` bleibt bei dieser Metadatenabfrage
`false`. `self_install_supported` beschreibt die Build-Fähigkeit: mit festem
Signierschlüssel unter Linux und bei eigenständigen Windows-MSVC-Builds `true`;
bei Windows-MinGW-Entwicklungsbuilds `false`. Nicht vorhandene Angaben sind `null`.
Kein öffentlich zugängliches Release (HTTP 404, möglicherweise auch ein
nicht zugängliches Repository) und kein kompatibles Paket verwenden Exitcode 3;
eine erfolgreich festgestellte Version Exitcode 0. Netzwerk-/HTTP-Fehler,
ungültige Metadaten und Abbruch bleiben Fehler und werden nicht als „aktuell“
ausgegeben. Fehler vor einem Prüfergebnis nutzen den normalen Fehlerpfad.

Ein App-Update wird ausdrücklich mit folgendem Befehl gestartet:

```sh
helium_drm_fixer --update-app
```

Der Befehl lädt ausschließlich ein neueres signiertes Paket aus dem festen
Fork, prüft alle Dateien und startet eine private Kopie der **bisherigen** App
als Helfer. Der Prozess beendet sich danach. Exitcode 0 und die Meldung
`scheduled` bedeuten, dass die Übergabe angenommen wurde; die Installation
erfolgt anschließend. Das heruntergeladene Programm wird nicht automatisch
gestartet. Ohne neueres kompatibles/signiertes Paket gilt Exitcode 3.
Der Programmname muss `helium_drm_fixer.exe` beziehungsweise `helium_drm_fixer`
bleiben, und der Ordner muss für den Benutzer beschreibbar sein. Keine Erhöhung
auf Administrator-/Root-Rechte. MinGW-Entwicklungsbuilds mit externen Runtime-DLLs
unterstützen den produktiven Selbstupdate-Befehl nicht.

Der ausgegebene `Job`-Pfad enthält das dauerhafte Ergebnis:

```sh
helium_drm_fixer --app-update-status "ABSOLUTER-JOB-PFAD" --json
```

Zustände: `waiting_for_parent`, `applying`, `installed`, `restored`, `failed`.
Nur `installed` beziehungsweise `restored` bestätigen den Abschluss. Bei
`failed` liefern `exit_code` und `detail` den Fehler; der Statusbefehl gibt
denselben Fehlercode zurück. Statusabfragen laden nichts und schreiben nichts.
Bei `waiting_for_parent` oder `applying` ist die Operation noch nicht als
abgeschlossen bestätigt; nach einem Helferabsturz kann dieser Zustand bestehen
bleiben und eine ausdrückliche Wiederherstellung nötig sein.

Für Wiederherstellung oder Rücknahme des letzten App-Updates:

```sh
helium_drm_fixer --restore-app "ABSOLUTER-PFAD-ZUR-helium_drm_fixer"
```

Unter Windows endet der Zielname auf `.exe`. Falls die Programmdatei nach
einem Absturz zwischen den Umbenennungen fehlt oder nicht startet, denselben
Befehl mit dem beim Update ausgegebenen **Recovery helper** ausführen:

```powershell
& 'C:\PFAD\.helium-app-update-jobs\job-ID\update-helper.exe' --restore-app 'C:\PFAD\helium_drm_fixer.exe'
```

Unter Linux entsprechend den aufbewahrten `update-helper` verwenden. Auch die
Wiederherstellung wird nach dem Ende des aufrufenden Prozesses ausgeführt und
liefert einen neuen Job-Pfad. `.helium-app-update` und `.helium-app-update-jobs`
neben der App enthalten Backups, geprüfte Pakete, Helfer und Statusdateien;
sie werden nicht automatisch gelöscht. Während eines laufenden oder
unterbrochenen Updates für die Wiederherstellung aufbewahren.
Die spätere GUI soll beim Start im Hintergrund prüfen,
unten rechts ihre App-Version und bei einem Update einen `Aktualisieren`-Knopf
anzeigen. Installation erfolgt nach einem ausdrücklichen Befehl oder Klick.
Die vorhandenen CDM-Modi `--check` und `--dry-run` bleiben offline.

Aus einem mit `cmake --install` vorbereiteten Verzeichnis erzeugt das Tool
`tools/package_app_release.py` die ZIP-Datei und `ZIPNAME.manifest.json`:

```powershell
New-Item -ItemType Directory -Path build/release-files -Force
python tools/package_app_release.py --staging build/package --version 0.1.0 --platform windows-x64 --output build/release-files
```

Unter Linux das Verzeichnis mit `mkdir -p build/release-files` anlegen und
`--platform linux-x86_64-ubuntu24.04` verwenden. Das Ausgabeverzeichnis
muss vorhanden, leer für diese Versionsdateien und vom Staging getrennt sein.
Die Versionsangabe muss zum gebauten Programm passen; das Tool führt keine
staged Binärdateien aus. Bekannte App-/Laufzeitdateien, README und Projekt-/
Bibliothekslizenzen werden aufgenommen. Links, Reparse Points, unbekannte Dateien,
fehlende oder unvollständige Laufzeiten und bestehende Ausgabedateien werden
abgelehnt. Gleiche Eingaben ergeben mit derselben Toolchain gleiche Paketdateien.

Mit `--signing-key /sicherer/pfad/helium-release.pem` kommt zusätzlich
`ZIPNAME.manifest.sig` hinzu. Ein verschlüsselter Schlüssel kann über
`--key-password-env FIXER_RELEASE_KEY_PASSWORD` entsperrt werden; die Variable
enthält die Passphrase, der Befehl nur deren Namen. Das Tool benötigt OpenSSL,
optional über `--openssl` angegeben. Für Windows-OpenSSL einen ASCII-Dateinamen
für den Schlüssel verwenden; sein Verzeichnis darf Unicode-Zeichen enthalten.
Private Schlüssel müssen außerhalb von Staging und Ausgabe liegen und werden
nicht in das Paket kopiert. Ohne Schlüssel ist die Ausgabe ausdrücklich ein
unsignierter Kandidat.

Für CI-Artefakte ist `tools/sign_app_candidate.py` der bevorzugte Signierweg.
Die Actions-Artefakte `windows-x64-unsigned-update-candidate` und
`linux-x86_64-unsigned-update-candidate` enthalten bereits das fertige App-ZIP
und sein Manifest. Nur die äußere Actions-Download-ZIP entpacken; die innere
App-ZIP unverändert lassen. Zuerst ohne Schlüssel prüfen:

```sh
python tools/sign_app_candidate.py --candidate build/release-input/helium-drm-fixer-cpp-0.1.0-windows-x64.zip --check-only
```

Der Check liest beide Plattformformate auch plattformübergreifend, prüft aber
keine Herausgebersignatur (`signature_verified: false`). Er wird auch in CI
ausgeführt. Für ein Selbstupdate-Paket werden externe Runtime-DLLs abgelehnt.
Zum lokalen Signieren anschließend `--signing-key`, `--public-key
keys/app-update-public.der`, `--output` und bei verschlüsseltem Schlüssel
`--key-password-env FIXER_RELEASE_KEY_PASSWORD` angeben; `--check-only` entfällt.
Die Passphrase muss dafür verdeckt abgefragt und vorübergehend über diese
Umgebungsvariable bereitgestellt werden. Privaten Schlüsselinhalt und Passphrase nicht in Git
oder Befehlsargumente kopieren. OpenSSL kann mit `--openssl` ausgewählt werden.

Der Signierer gleicht den privaten mit dem separat angegebenen öffentlichen
Projektschlüssel ab und prüft die erzeugte Signatur erneut. Er übernimmt ZIP
und Manifest bytegenau, ohne Entpacken, Neuverpacken oder Ausführen des Payloads.
Der Ausgabeordner darf noch nicht existieren; sein Elternordner muss existieren.
Ein abgebrochener Schreibvorgang kann einen unvollständigen Ausgabeordner
hinterlassen. Für einen neuen Versuch einen neuen Ausgabepfad verwenden.

Das fertige Paket mit einer vertrauenswürdigen App derselben Plattform prüfen:

```sh
helium_drm_fixer --verify-app-release PFAD/helium-drm-fixer-cpp-0.1.0-linux-x86_64-ubuntu24.04.zip --json
```

Unter Windows entsprechend `.exe` und das Windows-Paket verwenden. Der Befehl
nutzt ausschließlich den eingebauten öffentlichen Schlüssel und prüft Signatur,
Manifest, ZIP, Dateihashes und Binärformate. Er lädt nichts, entpackt nur im
Speicher und installiert/startet nichts (`installation_performed: false`).
Die Offline-Prüfung erlaubt auch dieselbe oder eine ältere Paketversion;
`--update-app` verlangt weiterhin eine neuere Version. Ein Paket für die andere
Plattform wird abgelehnt. Vor der Veröffentlichung beide Plattformen nativ
prüfen und alle drei Dateien pro Plattform unverändert hochladen. Die CI
veröffentlicht und signiert weiterhin nichts automatisch.

Das Manifest enthält Schema, App-/Repository-Identität, Version, Plattform,
Paketname/-größe/-SHA-256 und ein Inventar aus Dateipfaden, Größen, Hashes und
Ausführungskennzeichen. Signiert werden die exakten UTF-8-Bytes einschließlich
abschließendem Zeilenumbruch, vorangestellt der ASCII-Kontext
`Helium DRM Fixer app update manifest v1` mit einem NUL-Byte. Das Verfahren ist
RSA-PKCS#1-v1.5 mit SHA-256, RSA-3072/4096 und Exponent 65537.

Der öffentliche Schlüssel wird als DER-SubjectPublicKeyInfo beim Build über
`-DFIXER_APP_UPDATE_PUBLIC_KEY=/pfad/zum/public.der` fest eingebaut. Ohne diese
Konfiguration lehnt die native Manifestprüfung signierte Pakete ab. Presets und
CI verwenden `keys/app-update-public.der` als festen öffentlichen Release-Schlüssel.
Sein SHA-256-Fingerabdruck ist
`37AC29F8AED81ACD34E86683A90E3A7976C79DBF612A847763EC2A40795A6F7F`.
Bei direkter CMake-Konfiguration ohne Preset die Option ausdrücklich angeben.
Es gibt keinen Vertrauenstausch über heruntergeladene Metadaten. Der private
Schlüssel wurde vom Maintainer lokal eingerichtet und bleibt außerhalb des Repos;
Build und Prüfung benötigen ausschließlich den öffentlichen Teil.

Die native Schnittstelle prüft Signatur, erwartete Version, Plattform und
Manifeststruktur; `verify_app_package_digest` prüft anschließend Größe und Hash
der ZIP-Bytes. `unpack_app_package` verlangt ein zuvor signaturgeprüftes Manifest
und entpackt ausschließlich im Arbeitsspeicher. Die Dateiliste muss exakt passen;
jede Datei wird auf Größe, SHA-256, regulären Dateityp und die vorgesehenen
Berechtigungen geprüft. Links, zusätzliche/fehlende Dateien, doppelte oder
abweichende Pfade, CRC-Fehler und falsche Binärformate werden abgelehnt.
Dateien sind auf 64 MiB, das Paket und die Summe auf je 128 MiB begrenzt.
Erst nach vollständiger Prüfung werden die Dateiinhalte zurückgegeben.
Das ist keine Freigabe zur Installation und schreibt keine Dateien.
`stage_app_package` kann ein so geprüftes Paket anschließend in einem bereits
vorhandenen privaten Staging-Verzeichnis vorbereiten. Es legt einen neuen,
zufälligen Unterordner exklusiv an und überschreibt keine bestehenden Dateien.
Dateien werden geschrieben, synchronisiert und erneut vollständig auf ihr
Inventar und ihre Hashes geprüft, bevor der Unterordner von `.partial` auf
`.ready` umbenannt wird. Unter Linux bleiben Verzeichnisse und Programm privat
mit Modus 0700, andere Dateien mit 0600; unter Windows wird die private ACL
verwendet. Fehler können isolierte Reste hinterlassen, auch einen bereits
umbenannten Ordner bei einem anschließenden Synchronisierungsfehler.
Ein `.ready`-Name erlaubt keine Installation: Signatur und Dateien müssen vor
einem späteren Austausch erneut geprüft werden. Das laufende Programm wird
durch diesen Vorbereitungsschritt weder ersetzt noch gestartet.
`prepare_app_update` verbindet die feste Release-Abfrage mit Download und
Staging. Die Release-Metadaten müssen ein neueres Paket, dessen Manifest und
Signatur mit exakten Dateinamen, Download-URLs und begrenzten Größen enthalten.
Alle Start-URLs müssen zum festgelegten Repository unter `github.com` gehören.
Es ist genau eine HTTP-302-Weiterleitung auf
`release-assets.githubusercontent.com/github-production-release-asset/…`
zulässig; andere Ziele oder weitere Weiterleitungen werden abgelehnt.
Ein mitgelieferter Weiterleitungs-Body ist auf 8 KiB begrenzt; endgültige
Dateien müssen exakt ihrer angekündigten Größe entsprechen.
TLS-Zertifikate und öffentliche DNS-Adressen werden für beide Hosts geprüft,
die Verbindung bleibt an die geprüfte Adresse gebunden. Es gibt keine Proxy-
oder Token-Unterstützung. Für Metadaten und alle Downloads gilt ein gemeinsames
Netzwerkbudget von 120 Sekunden.

Manifest (höchstens 64 KiB) und Signatur (384/512 Bytes) werden zuerst geladen.
Erst nach gültiger Signatur und Übereinstimmung der signierten mit der
angekündigten Paketgröße wird das ZIP geladen (höchstens 128 MiB).
Ohne eingebauten öffentlichen Schlüssel beginnt die Anwendung keine dieser
Vorbereitungsanfragen. Das Ergebnis enthält den Staging-Pfad sowie die exakten
signierten Manifest-/Signaturbytes für die spätere erneute Prüfung. Diese Bytes
werden außerdem als `app-update.manifest.json` und `app-update.manifest.sig`
im privaten Staging gespeichert, synchronisiert und zurückgelesen.

`read_prepared_app_update` kann die Übergabe in einem neuen Prozess ausschließlich
lesend prüfen: fest eingebauter öffentlicher Schlüssel, erwartete neuere Version,
privater Besitzer/Ordner, exaktes Dateiinventar, Größen, SHA-256 und Binärformate.
Zusätzliche Dateien oder leere Fremdverzeichnisse, fehlende Metadaten, Links und
Hardlinks werden abgelehnt. Das Ergebnis enthält die frisch geprüften Dateibytes
im Speicher; ein späterer Austausch muss die veränderlichen Staging-Dateien
dadurch nicht erneut öffnen. Unvollständige Übergaben bleiben gesperrt.
`install_prepared_app_update` implementiert den Offline-Dateiaustausch: erneute
Signatur-/Inventarprüfung, absoluter Zielpfad, erwarteter Hash der bisherigen
Programmdatei und privates Transaktionsverzeichnis `.helium-app-update` neben
der Anwendung. Es ersetzt ausschließlich die Programmdatei eines eigenständigen
Pakets; Pakete mit externen Runtime-DLLs werden abgelehnt. Die Dokumentation
bleibt im Staging. Backup und Journal bleiben für die Wiederherstellung erhalten.
Bei Fehlern oder Abbruch wird zurückgerollt. `restore_app_update` kann auch nach
einem Prozessabsturz fortsetzen, selbst zwischen Umbenennung und Journal-Update.
Veränderte Ziele oder Backups werden nicht überschrieben oder gelöscht.

Der native Helfer hält einen Windows-Prozesshandle beziehungsweise unter Linux
ein pidfd und gleicht PID, Startzeit, Image-Pfad und bisherigen EXE-Hash ab.
Die Startentscheidung wird erst nach der Bereitschaft des Helfers dauerhaft
geschrieben; bei vorherigem Abbruch hat eine Abbruchdatei Vorrang. Maximal
20 Sekunden für Bereitschaft/Startentscheidung und 60 Sekunden auf das Ende
des Elternprozesses. Danach erneute Signatur-/Inventarprüfung und Offline-
Transaktion. Der Helfer läuft ohne neues Konsolenfenster beziehungsweise mit
umgeleiteten Standardstreams; das Ergebnis steht im privaten Job-Verzeichnis.
Abgeschlossene Aufträge können nicht erneut ausgeführt werden. Weder CLI noch
Auftragsdatei können einen anderen öffentlichen Prüfschlüssel konfigurieren.
Zwischen den Umbenennungen kann der Zielpfad kurz fehlen; der persistente
Helfer ermöglicht dann die ausdrückliche Wiederherstellung.
Der Release-Check lädt weiterhin keine Signaturdateien nach und sein JSON-Feld
`package_verified` bleibt `false`.
Die CI erhält keinen privaten Schlüssel und erzeugt weiterhin nur Kandidaten.

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
Kernschnittstellen-Test prüft Phasenreihenfolge, Metadaten, Callback-Ausnahmen,
Abbruch an sechs Installationsgrenzen, kritisches Restore und fehlende direkte
Konsolenausgabe. Die aktiven API-Aufrufe verwenden ausschließlich synthetische CDMs.
Ein zusätzlicher
CTest-Lauf führt 45 Szenarien mit der tatsächlichen Programmdatei aus:
Installation, Update, Restore, Crash-Recovery, Exitcodes und Unicode-Pfade.
Er verwendet ausschließlich synthetische PE-/ELF-Header in separaten temporären
Profilen; die Dateien werden nicht als Bibliotheken geladen. Quell-, Ziel-,
Home- und Cachepfade sind isoliert. Eine laufende Helium-Instanz blockiert auch
diesen Test; es gibt keinen Test-Bypass der Prozessprüfung. Dateisystem-Snapshots
prüfen verbleibende Inhalte und Änderungszeiten der schreibfreien und abgelehnten
Aufrufe. Sie erfassen keine zwischenzeitlichen Schreib-/Lösch-Systemaufrufe und
belegen allein keine Netzwerkfreiheit.

Eine weitere CTest-Gruppe prüft die Installationserkennung mit 34 Windows-
Szenarien: numerische Auswahl, Program-Files-/Benutzerpfad-Fallbacks,
mehrdeutige Versionen, ungültige/gesperrte EXEs, Hardlinks, Junctions sowie
Installieren, Update, Restore und erneute Auflösung nach einem Versionswechsel.
Program Files einschließlich `ProgramW6432`, Benutzer- und Cachepfade sind dabei
auf temporäre Fixtures gesetzt. Unter Linux prüfen fünf Szenarien die
Optionskonflikte und die Beibehaltung der profilbezogenen Zielauswahl.

Eine weitere CTest-Gruppe prüft 87 Releasefälle unter Windows beziehungsweise
89 unter Linux mit kurzlebigen Testschlüsseln:
RSA-3072/4096, falsche/zu schwache/EC-Schlüssel, Signatur-Kontext, manipulierte
Manifeste und ZIPs, Plattform-/Versionsbindung, Inventar-/Pfadfehler, unveränderte
Ausgaben bei abgelehnten Aufrufen und verschlüsselte Schlüssel. Erneut signierte
ZIPs prüfen außerdem Links, Berechtigungen, fehlende/zusätzliche Dateien,
CRC-/Dateihashfehler, Binärformate sowie gespeicherte und leere Dateien. Die synthetischen
Staging-Fälle prüfen zudem private Rechte, getrennte Vorbereitungen, den Erhalt
bestehender Dateien und Ablehnung von Abbruch, beschädigten Paketen sowie
fehlenden, relativen, verlinkten oder unter Linux nicht privaten Elternordnern.
Der vollständige Downloadablauf wird mit einem kontrollierten Transport geprüft:
gültige Pakete erreichen das Staging, falsche Schlüssel/Signaturen stoppen vor
dem Paketdownload, beschädigte Pakete vor dem Schreiben. Fehlende Signaturen,
veraltete Versionen, Abbruch und fehlender Vertrauensanker lösen keine Asset-Anfragen aus.
Persistierte Übergaben werden in einem neuen Prozess geprüft, auch nach
Manipulation von Signatur, Manifest, Nutzdateien und Ordnerstruktur. Die Prüfung
darf keine Dateien schreiben und akzeptiert keine fehlenden oder verlinkten Ziele.
Optional prüft `tests/release_packages.py --staging-space /pfad` auf einem
separaten begrenzten Linux-Testdateisystem mit weniger als 2 MiB freiem Platz,
dass ein Schreibfehler keinen `.ready`-Ordner veröffentlicht. Die synthetischen
Releaseprogramme werden nicht ausgeführt. Diese Testschlüssel werden weder im
normalen Programm verankert noch als Release-Vertrauensanker mitgeliefert.

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

Unter Windows prüft ein separates Skript echte NTFS-Platzmangelfehler:

```powershell
# In einer Administrator-Sitzung nach dem Build:
./tools/test_windows_space.ps1 -TestExecutable ./cmake-build-debug/fixer_tests.exe
```

Es erzeugt ein neues, auf 32 MiB begrenztes VHD im Build-Verzeichnis, prüft
dessen Identität vor dem Partitionieren/Formatieren und entfernt es anschließend.
Bestehende Datenträger werden nicht als Testziel angenommen. Der native Test
verlangt zusätzlich ein kleines NTFS-Volume mit dem Label `FIXER_SPACE_TEST`.
Die Fälle prüfen teilweises Staging, Update-/Restore-Grenzen, Speicherplatz-
Vorprüfung und fehlgeschlagenen Journalersatz samt Erhalt der Originaldateien.
Kleine Erstinstallationsjournale können in der NTFS-MFT verbleiben; deshalb
verwenden die Journal-Fehlerfälle eine bestehende Installation mit größerem Inventar.
Dieser Administrator-Test läuft separat von CTest und als eigener Windows-CI-Schritt.

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
