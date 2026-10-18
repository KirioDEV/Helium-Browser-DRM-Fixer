# Quellen und Lizenzen

Dieses Projekt ist die C++-Umsetzung der vorherigen Go-Implementierung.
Die Projektlizenz steht in [LICENSE](LICENSE). Lokale Go-Referenzordner gehören
nicht zum veröffentlichten C++-Paket.

| Bestandteil | Version / Bindung | Lizenz | Quelle |
| --- | --- | --- | --- |
| nlohmann/json | 3.12.0, SHA-256 in CMakeLists.txt | MIT | https://github.com/nlohmann/json |
| miniz | 3.1.2, SHA-256 in CMakeLists.txt | MIT | https://github.com/richgel999/miniz |
| Slint (optionale UI-Vorschau) | 1.18.1, SHA-256 in cmake/SlintGui.cmake | Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0 | https://github.com/slint-ui/slint |
| Corrosion (nur GUI-Build) | 0.6.1, SHA-256 in cmake/SlintGui.cmake | MIT | https://github.com/corrosion-rs/corrosion |
| libcurl (Linux) | Systempaket, mindestens 7.85 | curl license | https://curl.se/docs/copyright.html |
| OpenSSL (Linux) | Systempaket, mindestens 3.0 | Apache-2.0 | https://www.openssl.org/source/license.html |
| MinGW-Compilerlaufzeiten (Windows-MinGW) | aus der gewählten Toolchain | jeweilige Runtime-Lizenzen mit Ausnahmen | https://www.mingw-w64.org/ und https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html |

Windows nutzt WinHTTP, Crypt32, BCrypt und weitere Windows-Systembibliotheken;
sie werden nicht in das Paket kopiert. Linux-Systembibliotheken werden dynamisch
gebunden und nicht als eigene Builds ausgeliefert.

Die Slint-Vorschau wird noch nicht in Release-Pakete installiert. Ihr
`AboutSlint`-Widget ist über das Hilfe-Menü erreichbar. Vor ihrer Auslieferung
müssen zusätzlich die Lizenztexte der tatsächlich eingebundenen Rust-Abhängigkeiten
und Compilerlaufzeiten vollständig erfasst und mitgeliefert/eingebettet werden.

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

Abweichungen vom ursprünglichen Plan: Windows-native HTTP/Kryptografie statt
libcurl/OpenSSL auf Windows; miniz statt libarchive für ZIP; ein strikt begrenzter
Decoder für die drei flachen CRX3-Protobuf-Nachrichten statt einer vollständigen
Protobuf-Laufzeit. Kryptografische Algorithmen kommen ausschließlich aus
CNG bzw. OpenSSL. Die Parser werden mit negativen Tests und Fuzzing geprüft.
