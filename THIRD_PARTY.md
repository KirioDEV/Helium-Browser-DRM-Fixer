# Quellen und Lizenzen

Dieses Projekt ist die C++-Umsetzung der vorherigen Go-Implementierung.
Die Projektlizenz steht in [LICENSE](LICENSE). Lokale Go-Referenzordner gehören
nicht zum veröffentlichten C++-Paket.

| Bestandteil | Version / Bindung | Lizenz | Quelle |
| --- | --- | --- | --- |
| nlohmann/json | 3.12.0, SHA-256 in CMakeLists.txt | MIT | https://github.com/nlohmann/json |
| miniz | 3.1.2, SHA-256 in CMakeLists.txt | MIT | https://github.com/richgel999/miniz |
| Slint (optionale GUI) | 1.18.1, SHA-256 in cmake/SlintGui.cmake | Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0 | https://github.com/slint-ui/slint |
| Corrosion (nur GUI-Build) | 0.6.1, SHA-256 in cmake/SlintGui.cmake | MIT | https://github.com/corrosion-rs/corrosion |
| libcurl (Linux) | Systempaket, mindestens 7.85 | curl license | https://curl.se/docs/copyright.html |
| OpenSSL (Linux) | Systempaket, mindestens 3.0 | Apache-2.0 | https://www.openssl.org/source/license.html |
| MinGW-Compilerlaufzeiten (Windows-MinGW) | aus der gewählten Toolchain | jeweilige Runtime-Lizenzen mit Ausnahmen | https://www.mingw-w64.org/ und https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html |

Windows nutzt WinHTTP, Crypt32, BCrypt und weitere Windows-Systembibliotheken;
sie werden nicht in das Paket kopiert. Die Linux-CLI bindet Systembibliotheken
dynamisch. Das separate GUI-AppImage bündelt einen Teil dieser Bibliotheken.

Die Slint-GUI hat eigene signierte Update-Pakete und wird nicht durch CLI-Pakete
ersetzt. Ihr `AboutSlint`-Widget ist über „Settings → About“ erreichbar. Die GUI-Paketierung
erfasst zusätzlich die Lizenztexte der tatsächlich ausgewählten Rust-Abhängigkeiten
und der Rust-Standardbibliothek.

Das Linux-GUI-AppImage enthält die Lizenztexte des über Cargo.lock gebundenen
Rust-Abhängigkeitsgraphen und der Rust-Standardbibliothek. Paketierung und
Versionsinventar stehen in `tools/collect_gui_licenses.py`. Für
im Crate fehlende Lizenzdateien enthält `tools/gui-license-supplements.json`
Quellen aus festen Upstream-Commits mit SHA-256. In Quelldateien enthaltene
Hinweise werden im Original mitgeliefert; Standardlizenztexte sind als solche
erkennbar und ersetzen keine erfundenen Copyright-Angaben. Für tatsächlich
gebündelte Linux-Bibliotheken werden die Copyright-/Lizenzdateien der
Distributionspakete, deren Quellpaketversionen und Quellverweise aufgenommen.
Die AppImage-Laufzeit hat einen eigenen beigefügten MIT-Lizenztext.
AppImage-Buildwerkzeuge sind nach Version und SHA-256 in
`tools/package_linux_gui.py` festgelegt und werden nicht mitverteilt.

Die Windows-GUI wird mit MSVC gebaut. `tools/package_windows_gui.py`
kopiert die EXE und bettet das zusätzliche Lizenz-/Quelleninventar als ZIP in
RCDATA-Ressource 104 ein. Das separat angebotene `gui-notices.zip` ist eine
bytegleiche lesbare Kopie; die EXE benötigt diese Datei nicht zum Start.
Die vorhandenen Lizenzressourcen 101–103 und das Anwendungsicon bleiben erhalten.
Slint/Rust und die MSVC-Laufzeit werden statisch gelinkt; Windows-System-DLLs
werden nicht kopiert. MinGW-Builds sind weiterhin lokale Entwicklungsbuilds und
werden von diesem Windows-Preview-Packager nicht zur Verteilung angenommen.

CMake installiert diese Drittanbieterhinweise, die Sicherheitsdokumentation,
README und Projektlizenz sowie die Lizenztexte von miniz und nlohmann/json
nach `share/helium-drm-fixer`. Die standalone Windows-MSVC-EXE enthält die
Projektlizenz und die Lizenztexte dieser beiden Bibliotheken zusätzlich als
eingebettete Ressourcen. Die MSVC-Compilerlaufzeit wird statisch eingebunden;
die Release-EXE benötigt keine separat mitgelieferten Compiler-Runtime-DLLs.
Für eine Veröffentlichung eines MinGW-Pakets zusätzlich die Lizenztexte und
Pflichten der konkret verwendeten Compilerlaufzeiten prüfen. Für MSVC-Pakete
die Microsoft-Runtime-Bedingungen prüfen. Build-Artefakte sind noch keine
rechtlich oder sicherheitstechnisch freigegebenen Releases.

Das Widevine-Paket ist proprietär und wird nicht mitgeliefert oder in CI-Artefakte
kopiert. Ein im Paket vorhandener LICENSE-Text wird bei der Installation erhalten.
Heruntergeladene Testpakete und synthetische Fixtures werden nicht als
Release-Bestandteile mitinstalliert.

Die Projektlizenz erteilt keine Rechte an Widevine. Maßgeblich bleiben die
jeweils anwendbaren Bedingungen des Rechteinhabers; siehe
[Googles Widevine-Hinweis](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/widevine/LICENSE).
Das Repository und die App-Releases hosten keine Widevine-Binaries. Die App
speichert bei Nutzung jedoch heruntergeladene Pakete, CDM-Dateien und Backups
lokal im Benutzerkonto. Sie lädt diese Dateien nicht zu diesem Projekt hoch,
entschlüsselt keine Streaminginhalte und extrahiert keine DRM-/Inhaltsschlüssel.
Das Projekt ist nicht mit Google, Widevine, imput oder dem Helium-Projekt
verbunden, wird nicht als deren offizielles Produkt herausgegeben und wird
nicht von ihnen gesponsert. Namen und Marken dienen nur
der Produktzuordnung. Der vollständige [Disclaimer](README.md#disclaimer)
beschreibt Umfang und Grenzen; er ersetzt keine erforderlichen Nutzungsrechte.

Abweichungen vom ursprünglichen Plan: Windows-native HTTP/Kryptografie statt
libcurl/OpenSSL auf Windows; miniz statt libarchive für ZIP; ein strikt begrenzter
Decoder für die drei flachen CRX3-Protobuf-Nachrichten statt einer vollständigen
Protobuf-Laufzeit. Kryptografische Algorithmen kommen ausschließlich aus
CNG bzw. OpenSSL. Die Parser werden mit negativen Tests und Fuzzing geprüft.
