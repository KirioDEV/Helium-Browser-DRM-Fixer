# Sicherheitsmodell und Validierungsstand

Dieses Dokument beschreibt den implementierten Schutzumfang und bekannte
Prüfgrenzen. Es ersetzt kein unabhängiges Sicherheitsaudit. Die Angaben zu
CDM-Downloads beziehen sich auf Widevine; das getrennte App-Update-Verfahren
und seine GitHub-Quelle sind im letzten Abschnitt beschrieben.

## Schutzmaßnahmen für CDM-Download und Installation

- Nur zwei belegte Google-Downloadhosts: `dl.google.com` und
  `edgedl.me.gvt1.com`; Metadaten ausschließlich vom festgelegten Google-Endpunkt.
- HTTPS, System-Zertifikatsprüfung, Hostnamenprüfung, öffentliche DNS-Adressen,
  kontrollierte Weiterleitungen und Antwortgrößenlimits. Keine Proxy-Unterstützung,
  damit ein Proxy die Adressrichtlinie nicht umgeht.
- Das 120-Sekunden-Transferbudget eines HTTP-Aufrufs wird über alle Redirects
  geteilt. Windows überwacht asynchrone Sende-/Empfangsoperationen und wartet bei
  deren Schließen auf den letzten Callback, bevor Kontext und Lesepuffer freigegeben
  werden. Deklarierte Übergrößen und unvollständige Content-Length-Antworten werden
  abgelehnt; tatsächlich empfangene Bytes bleiben auch ohne Längenangabe begrenzt.
- Download-Metadaten benötigen einen SHA-256-Wert, passende App-ID,
  Protokollversion, vollständige Download/CRX3-Pipeline und konsistente Input-Hashes.
- Alle CRX3-Proofs werden kryptografisch geprüft. Mindestens ein gültiger
  Signaturschlüssel muss aus seinem SHA-256-Hash die festgelegte Widevine-ID
  `oimompecagnajdejgnnjijobebaeigek` ergeben. Ein selbstsigniertes beliebiges Paket
  genügt nicht. Das Verfahren folgt Chromiums Komponentenidentität;
  es benötigt keine heruntergeladenen Vertrauensanker.
- Der 2017er Web-Store-Publisher-Schlüssel wird nicht zusätzlich verlangt:
  die Komponentenidentität ist der hier verwendete Vertrauensanker, keine
  Behauptung einer Web-Store-Zertifizierung.
- Maximal 64 MiB Paket, 1 MiB Update-Metadaten, 1 MiB CRX-Header,
  256 ZIP-Einträge und 128 MiB deklarierter entpackter Inhalt. Nur Manifest,
  plattformgerechte CDM-Bibliothek und optional LICENSE werden materialisiert.
  Daten bleiben bis zur Prüfung begrenzt im Speicher; es wird kein untrusted ZIP
  direkt ins Dateisystem entpackt.
- Archivpfade, Sonderdateien, Linkattribute, Namenskollisionen und
  Dateiverzeichniskollisionen werden abgelehnt. PE-/ELF-x86_64-Strukturprüfung
  erfolgt ohne das Laden der Bibliothek.
- Cachepakete werden vor jeder Verwendung erneut auf Hash und Signatur geprüft;
  ein entpackter Cache wird nicht wiederverwendet.
- Exklusive Dateierzeugung, native No-Follow-Dateihandles, private Rechte/ACLs,
  Symlink-/Reparse-Prüfung, Hardlink-Ablehnung anhand der Linkanzahl des
  geöffneten Dateihandles und exklusive Installationssperre.
- Datei-, Journal-, Sperr- und Verzeichnisoperationen öffnen Elternverzeichnisse
  komponentenweise ohne Linkauflösung. Windows hält dabei Handles ohne
  Delete-Sharing. Linux verwendet Verzeichnisdeskriptoren mit `openat`, `mkdirat`
  und `renameat`; Installation/Restore verwenden `renameat2(RENAME_NOREPLACE)`.
  Bereits vorhandene oder gleichzeitig erzeugte Umbenennungsziele werden dadurch
  auch dann nicht ersetzt, wenn sie leere Verzeichnisse sind.
- Quellgrößen und Manifestversion werden vor Transaktionsdateien geprüft.
  Bereits gemeldeter Abbruch und nicht ausreichender verfügbarer Speicherplatz
  führen ebenfalls vor deren Erzeugung zum Fehler.
- Staging und Backup liegen auf demselben Dateisystem wie das Ziel.
  Journale und Dateien werden vor Zustandswechseln geflusht. Linux synchronisiert
  Verzeichnisse; Windows verwendet Write-Through-Umbenennungen.
- Linux-Installation, Rollback und Restore halten Ziel-Elternordner und
  Verwaltungsordner bis zum Ende geöffnet. Staging, Sperre, Inventar,
  Journal und Umbenennungen benutzen diese Deskriptoren und deren relativ
  geöffnete Unterverzeichnisse. Inventartraversierung folgt keinen Links,
  ist auf 1024 Einträge und 32 Verzeichnisebenen begrenzt und öffnet Dateien
  relativ zum jeweils gehaltenen Verzeichnis.
- Bei einem erkannten Austausch der sichtbaren Verzeichnispfade wird abgebrochen.
  Automatisches Rollback greift weiterhin auf die ursprünglichen Verzeichnisse zu.
  Ein separat gestartetes Restore prüft die Pfadbindung auch nach seinen
  Umbenennungsphasen und behält bei Unterbrechung das Journal für einen Folgelauf.
- Restore vergleicht die tatsächlichen Dateiinhalte mit dem gespeicherten
  Inventar und überschreibt keine zwischenzeitlich modifizierte Installation.

## Grenzen

Eine kompromittierte Sitzung desselben Benutzers, Administrator/root oder ein
kompromittiertes Betriebssystem können Dateien, Journale und das Programm
selbst verändern. Dies liegt außerhalb des Schutzmodells. Gehaltene Verzeichnisse
sind keine Linux-Schreibsperre gegen denselben Benutzer: Einzelne Dateien oder
Unterverzeichnisse können weiterhin manipuliert werden. Inventarprüfung und
Umbenennung sind keine gemeinsame atomare Operation. Die Bindung der
Transaktionswurzeln ersetzt keine vollständige Abwehr sämtlicher solcher Rennen.
Bei ausgetauschten sichtbaren Pfaden muss deren Zuordnung vor einem erneuten
Restore geklärt werden; das Programm verschiebt die fremden Ersatzordner nicht zurück.
Für die geöffneten Verzeichniswege werden Leserechte benötigt; fehlen sie,
wird abgebrochen. Linux-Dateisysteme müssen `RENAME_NOREPLACE` unterstützen;
es gibt keinen unsicheren Fallback auf ersetzendes `rename()`.

Beide Plattformen pinnen die vorab geprüfte DNS-Adresse: Linux über
`CURLOPT_RESOLVE`, Windows über `WINHTTP_OPTION_RESOLUTION_HOSTNAME` auf dem
Request-Handle. Der ursprüngliche Hostname bleibt für TLS-SNI, Zertifikatsprüfung
und HTTP-Host erhalten. Die tatsächlich verbundene IP muss zusätzlich exakt mit
der gepinnten Adresse übereinstimmen. Ein fehlgeschlagenes Pinning bricht ab;
es gibt keinen Fallback auf eine erneute freie Auflösung durch den HTTP-Client.
Alle bis zu 64 gelieferten DNS-Adressen müssen die Public-IP-Regeln erfüllen;
eine private Adresse neben einer öffentlichen genügt zur Ablehnung. IPv6 erlaubt
nur Global Unicast und schließt zusätzlich `2001::/23`, 6to4 und die beiden
Dokumentationsbereiche aus. Öffentliche Spezialausnahmen in `2001::/23` werden
bewusst ebenfalls abgelehnt, da die festen Downloadhosts sie nicht benötigen.
TLS und Paket-Signaturprüfung bleiben verpflichtend. Die DNS-Vorabfrage läuft
jetzt in einem einzigen Worker, dessen Wartezeit auf zehn Sekunden und das
verbleibende HTTP-Gesamtbudget begrenzt ist. Der Aufrufer prüft Abbruch und
Deadline während des Wartens in höchstens 20-Millisekunden-Intervallen, zuzüglich
Scheduling-Verzögerungen. Eingaben und Ergebniszustand gehören dem Worker-Task;
er hält keine Referenzen auf bereits zurückgekehrte Aufrufe oder Testeinstellungen.

Die native Betriebssystem-Auflösung selbst wird dabei nicht gewaltsam beendet.
Bleibt sie nach Timeout/Abbruch aktiv, weist der einzelne Worker weitere
Auflösungsversuche ab. Es gibt keine wachsende Warteschlange oder zusätzliche
Resolver-Threads. Ein spätes Ergebnis löst keine Verbindung aus und wird nicht
für einen späteren Aufruf wiederverwendet. Nach Rückkehr der alten Auflösung ist
ein neuer Versuch möglich. Beim Programmende wird ein inaktiver Worker regulär
beendet; ein weiterhin blockierter Worker verzögert den Prozessabschluss nicht.

Ein Stromausfall ist anspruchsvoller als ein Prozessabbruch: Garantien hängen
auch von Dateisystem, Laufwerk und dessen Flush-Verhalten ab. Es gibt keinen
universellen atomaren Austausch zweier nichtleerer Ordner.

Eine lokale Chrome-Quelle besitzt keine CRX3-Herkunftsgarantie und muss vom
Benutzer ausdrücklich ausgewählt werden. Selbst korrektes Widevine kann bei
Streamingdiensten wegen Browseridentität, HDCP oder weiterer Anforderungen scheitern.

## Getestet und noch offen

Lokal geprüft: Windows-MinGW-Build; Ubuntu-24.04-GCC-Build;
Ubuntu-Clang-Build mit AddressSanitizer/UndefinedBehaviorSanitizer;
Options-, Pfad-, Hash-, Manifest-, Archiv-, Metadaten- und Recovery-Tests;
fünf echte Prozessabbrüche mit Wiederherstellung.
Die im Projektverlauf ausgeführten CTest-Prüfungen umfassen Windows-MinGW,
Linux-GCC und Linux-Clang/ASan/UBSan. Die nachfolgenden Fallzahlen beschreiben
historische Prüfläufe, nicht die aktuelle Gesamtzahl der Tests.
Darunter sind 53 native Windows- bzw. 52 native Linux-
HTTPS-Szenarien mit lokalen TLS-Servern: unbekannte CA, falscher Hostname,
abgelaufenes Zertifikat, Redirect-Regeln, POST-Redirect, deklarierte/unbekannte
Größen, Chunked Transfer, abgeschnittene Antwort, Header-/Body-Stillstand,
gemeinsames Redirect-/Streaming-Zeitbudget und Abbruch im Stillstand/Streaming.

Diese Fixtures laufen in einem separat kompilierten Testprogramm. Linux benutzt
eine ephemere CA-Datei. Nur der Windows-Testtransport toleriert eine unbekannte CA
für ein anschließend exakt per SHA-256 geprüftes Serverzertifikat; native Hostnamen-
und Datumsprüfungen bleiben aktiv. Die normale EXE enthält diese Testkonfiguration
nicht und verwendet die System-Zertifikatsprüfung. Es werden keine Test-CAs in
Systemspeicher importiert. Ein zusätzlicher Windows-Test verwirft einen falschen Pin.
CTest prüft außerdem, dass eine Testdiagnose nicht in der normalen EXE enthalten ist
und diese keine Fixture-CLI-Option akzeptiert.
Ein zusätzlicher CLI-Lauf prüft 45 Szenarien mit der normalen Programmdatei und
isolierten Home-/Cache-/Profilpfaden: Erstinstallation, Update, wiederholbares
Restore, fehlendes/ungültiges CDM, ungültige lokale Quellen und Pakete, Quelle im
Zielordner und Wiederherstellung nach echtem Prozessabbruch. Die Testpfade
enthalten Leerzeichen, Umlaute und CJK-Zeichen; das Windows-Crash-Testprogramm
liest seine Argumente jetzt wie die normale EXE über die Unicode-Kommandozeile.
CDM-Fixtures enthalten nur synthetische PE-/ELF-Header und werden niemals geladen.
Quellen und alte Installationsdateien einschließlich Änderungszeiten bleiben
erhalten. Snapshots der schreibfreien und abgelehnten CLI-Aufrufe prüfen den
verbleibenden Dateisystemzustand; eine Instrumentierung sämtlicher Schreib- und
Netzwerk-Systemaufrufe sowie echte Browser-/Streamingtests ersetzen sie nicht.
Echte Google-Pakete für Windows und Linux wurden auf Signatur, Struktur und
Version geprüft; manipulierte Kopien werden abgelehnt.
Der vollständige HTTPS-Download- und Prüfpfad wurde auf beiden Plattformen
gegen Google ausgeführt. 169 Assertions unter Windows bzw. 234 unter Linux
decken die zusätzlichen plattformspezifischen Fälle ab.
Zusätzlich geprüft: Abbruch an allen fünf Transaktionsgrenzen mit Rollback,
Hardlink-Ablehnung, manipulierte Backups und Journal-IDs, ungültige Quellen,
eine unter Windows ohne Delete-Sharing geöffnete DLL und fehlende
Linux-Schreibrechte bei einem unprivilegierten Benutzer.
Dateisystemtests erzeugen Umbenennungsziele gezielt zwischen Vorprüfung und
Systemaufruf. Unter Windows wird die Umbenennung geöffneter Elternverzeichnisse
blockiert; unter Linux werden deren Pfade gezielt durch Symlinks ersetzt und
die Verwendung der ursprünglichen Verzeichnisdeskriptoren bestätigt.
Weitere 16 Linux-Szenarien tauschen Ziel-Elternordner oder Verwaltungsordner
an fünf Installations- und drei Restore-Grenzen aus. Der Austausch wird erkannt,
Ersatzbestände und ihre Journale bleiben unverändert, und der ursprüngliche
Bestand wird automatisch zurückgesichert oder nach Wiederherstellung der
Pfadzuordnung per Restore wiederhergestellt. Inventar und Sperre werden außerdem
direkt nach dem Umbenennen ihres geöffneten Verzeichnisses geprüft.
Auf einem separaten 64-KiB-Test-Dateisystem wurde der Speicherplatzmangel
vor dem Anlegen von Transaktionsdateien erkannt. Zusätzlich wurde beim Schreiben
eines neuen Journals tatsächlich ENOSPC ausgelöst: Das vorherige Journal bleibt
erhalten, die teilweise geschriebene temporäre Datei wird entfernt. Dieser Fall
besteht mit GCC und mit Clang unter ASan/UBSan, einschließlich des neuen gebundenen
Journalzugriffs. Ein erweiterter Parser-Fuzz-Lauf
unter ASan/UBSan verarbeitete 215.118 Eingaben in 304 Sekunden ohne gemeldeten
Fehler; dies belegt keine vollständige Fehlerfreiheit.

Weitere 18 Linux-Fälle füllen ein eigenes 8-MiB-tmpfs während Staging,
Installation oder Restore, jeweils mit und ohne vorhandene Installation.
Sie prüfen einen tatsächlich teilweise geschriebenen CDM-Puffer, erhaltene
Original- und vorbereitete Ersatzdateien, gültige verbleibende Journale,
Cleanup temporärer Journaldateien und wiederholbares Restore nach Platzfreigabe.
Ein fehlgeschlagenes Staging verhindert auch eine erneute Installation nicht.
Die Linux-CI bindet dafür ein separates tmpfs ein.

Die erweiterten lokalen HTTPS-Fixtures speisen DNS-Fehler, leere/übergroße
Antwortmengen, öffentliche und gemischte private IPv4-/IPv6-Antworten sowie
geänderte Antworten bei Redirects ein. Die native Verbindung verwendet die
gepinnten Loopback-Adressen, während Host und TLS-SNI den freigegebenen
Hostnamen behalten; ein ausschließlich für die IP gültiges Zertifikat wird
abgelehnt. Diese CTest-Fixtures ändern weder Hosts-Datei noch System-DNS.

Weitere Worker-Tests prüfen DNS-Zeitlimit, gemeinsames Budget über Redirects,
Abbruch, ein verspätetes ungültiges Ergebnis nach Zerstörung der Testeinstellungen
und die spätere Wiederverwendung. 50 zusätzliche Prozessstarts pro Compiler
prüfen das reguläre Herunterfahren des Resolver-Workers.
Ein separater Linux-Container-Test mit normaler Produktions-CLI und tatsächlich
nicht antwortendem Loopback-DNS-Server bestätigt mit GCC und Clang/ASan/UBSan:
Die Anfrage endet nach etwa zehn Sekunden, SIGINT beendet sie innerhalb von
0,12 Sekunden, und das Programmende wartet nicht auf das 30-Sekunden-Zeitlimit
des System-Resolvers. Der Container hat kein externes Netzwerk; weder Hosts-Datei
noch DNS-Einstellungen des Hosts werden geändert. Dieser Test gehört nicht zu
CTest und verändert selbst auch keine Container-Resolver-Einstellungen.

Ein weiterer separater Linux-Container-Test (`tests/dns_rebinding.py`) prüft
sieben Fälle je Compiler mit UDP-DNS, dem wirklichen `getaddrinfo`-Pfad und dem
nativen HTTPS-Transport. Die Test-IP-Adressen 8.8.8.8 und 8.8.4.4 werden nur dem
Loopback-Interface dieses Containers zugewiesen; er besitzt kein externes Netz.
Der DNS-Server wechselt seine Antwort mit TTL null auf eine private Adresse.
Die erste Verbindung verwendet weiter die gepinnte öffentliche IP, ohne erneut
DNS abzufragen; eine unabhängige UDP-Abfrage bestätigt den tatsächlichen Wechsel.
Bei Redirects wird die neue private Antwort vor dem Verbindungsaufbau abgelehnt.
Ein neuer öffentlicher Peer ist nach erneuter Prüfung zulässig. Weitere Fälle
prüfen gemischte IPv4-/IPv6-Antworten, private Antworten und NXDOMAIN.
Der private Zielserver darf weder HTTP-Anfragen noch TLS-SNI erhalten; an den
öffentlichen Fixture-Servern bleiben ursprüngliches TLS-SNI und HTTP-Host erhalten.

Dieser Test verwendet das getrennt kompilierte Netzwerk-Testprogramm mit
System-DNS statt Antwortinjektion und einer privaten CA-Datei. Der normale Build
bleibt frei von diesem Modus. `NET_ADMIN` ist nur für die Loopback-Testadressen
im isolierten Container nötig; weder Host-Netzwerk noch System-Vertrauenskette
werden geändert. Der Test ist nicht Bestandteil des normalen CTest-Laufs.

13 native Windows-Platzmangelfälle wurden auf einem neu erzeugten 32-MiB-VHD
mit NTFS geprüft: teilweises Staging, fünf Update- und drei Restore-Grenzen,
Vorprüfung sowie zwei Journalersatz-Zugriffe. Die Originale bleiben erhalten;
nach Platzfreigabe sind erneute Installation und wiederholbares Restore möglich.
Die Fülldateien verwenden Write-Through; vor der Wiederaufnahme wird auf die
NTFS-Platzfreigabe gewartet. Kleine Erstinstallationsjournale können resident
in der MFT bleiben; Journalfehler werden mit einem größeren Altinventar erzwungen.
Unbekannte und unplausible Freiplatzwerte werden in der Vorprüfung abgelehnt.
Der separate Test wurde lokal mit MinGW ausgeführt und ist außerdem Teil der
MSVC-CI. Erfolgreiche vollständige GitHub-CI-Läufe wurden vom Maintainer bestätigt;
ein lokaler MSVC-Build wurde in der Entwicklungsumgebung nicht ausgeführt.

Noch nicht geprüft sind System-DNS-Stillstand und tatsächliches DNS-Rebinding
unter Windows.
Ein vorgeschalteter freier-Speicherplatz-Check reserviert keinen Speicherplatz;
andere Prozesse können ihn nach der Prüfung verbrauchen.

Noch keine Freigabe als umfassend auditiert. Ausstehend sind ein lokaler
MSVC-Lauf, Betrieb mit echten Helium-Installationen einschließlich Streaming,
separate AppImage-/Sandbox-Tests und langfristige Fuzz-/Vulnerability-Prüfungen.
ARM64, macOS, Flatpak und Snap sind nicht freigegeben.

## Primärquellen

- WinHTTP-DNS-Pinning: https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags#winhttp_option_resolution_hostname
- libcurl-DNS-Pinning: https://curl.se/libcurl/c/CURLOPT_RESOLVE.html
- IPv6-Sonderbereiche: https://www.iana.org/assignments/iana-ipv6-special-registry/

- CRX3-Struktur: https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx3.proto
- Chromium-Verifikation: https://github.com/chromium/chromium/blob/main/components/crx_file/crx_verifier.cc
- WinHTTP: https://learn.microsoft.com/en-us/windows/win32/winhttp/about-winhttp
- CNG-Signaturen: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature
- libcurl: https://curl.se/libcurl/
- libcurl-Größenlimit: https://curl.se/libcurl/c/CURLOPT_MAXFILESIZE_LARGE.html
- WinHTTP-Callback-Lebenszeit: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nc-winhttp-winhttp_status_callback
- Linux-Umbenennungsflags: https://github.com/torvalds/linux/blob/master/Documentation/filesystems/vfs.rst
- Windows-Verzeichnishandles und Sharing: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew

## App-Releasepakete und Vertrauensanker

App-Updates verwenden ausschließlich das festgelegte Repository
`KirioDEV/Helium-Browser-DRM-Fixer`. `--check-app-update` liest Metadaten des
neuesten öffentlichen stabilen Releases. Diese Abfrage prüft noch keine
Paketsignatur. Entwürfe und Prereleases werden nicht als Update-Ziel verwendet.

`--update-app` lädt Manifest, Signatur und Paket und prüft sie vor der Installation.
RSA-PKCS#1-v1.5/SHA-256 verwendet einen festen Signaturkontext und einen im Build
verankerten RSA-3072/4096-SPKI-Schlüssel. Der öffentliche Projektschlüssel liegt
in `keys/app-update-public.der`; private Schlüssel gehören nicht ins Repository.
Heruntergeladene Schlüssel werden nicht als Vertrauensanker übernommen. Ohne
konfigurierten öffentlichen Build-Schlüssel werden signierte App-Updates abgelehnt.

Die Signatur wird vor der Manifestauswertung geprüft. Identität, Plattform,
kanonische Version, Paketname/-größe/-hash und das vollständige begrenzte
Dateiinventar müssen zusammenpassen. ZIP-Pfade, Links, Sonderdateien und
Namenskollisionen werden abgelehnt. Jedes Nutzfile wird auf Größe und SHA-256,
die Programmdatei zusätzlich auf natives x86_64-PE-/ELF-Format geprüft.
Pakete für ein Selbstupdate dürfen keine externen Runtime-DLLs benötigen.
Windows-Selbstupdates sind deshalb auf standalone MSVC-Builds beschränkt;
lokale MinGW-Entwicklungsbuilds können Pakete prüfen, sich aber nicht selbst updaten.

Der Austausch wird erst nach dem Ende des aufrufenden Prozesses durch eine
private Kopie der bisherigen App ausgeführt. Prozessidentität und alter
Programmhash werden gebunden; der Helfer prüft die signierte Übergabe erneut.
Backup, Journal, Sperre und Wiederherstellung schützen die einzelne Programmdatei.
`scheduled` bestätigt nur die Planung. Erst `--app-update-status JOB --json`
mit `installed` beziehungsweise `restored` bestätigt den Abschluss. Es erfolgt
kein automatischer Start der neu heruntergeladenen Programmdatei. Der alte
Recovery-Helfer bleibt für Statusabfragen und `--restore-app` verfügbar.

Die CI baut und testet Windows mit MSVC sowie Linux mit GCC und Clang. Nur nach
erfolgreichen Build-Jobs eines main-Push-Laufs wird der Signierjob im selben
Workflow aufgerufen. Er prüft zusätzlich Build-Identität und Job-Ergebnisse.
Die Environment-Secrets `RELEASE_SIGNING_KEY_PEM` und
`RELEASE_SIGNING_KEY_PASSPHRASE` sind nur im Signierschritt verfügbar.
Der verschlüsselte Schlüssel wird temporär außerhalb der Upload-Verzeichnisse
geschrieben, gegen den öffentlichen Projektschlüssel abgeglichen und anschließend
entfernt. Die vorhandenen ZIP-/Manifestbytes bleiben unverändert; jede erzeugte
Signatur wird erneut geprüft. GitHub erhält durch diese Einrichtung ebenfalls
Zugriff auf den Schlüssel und seine Passphrase. Eine kompromittierte berechtigte
main-Änderung oder Signierumgebung liegt außerhalb dieser Paket-Vertrauenskette.
Der Workflow hat keine Schreibrechte auf Releases und veröffentlicht nichts.

Die App-Update-Signatur ist keine Windows-Authenticode-Signatur. Die EXE besitzt
derzeit keine bestätigte Windows-Herausgebersignatur; SmartScreen kann deshalb
beim Download und Start warnen.

Im bisherigen Projektverlauf bestanden 204 synthetische Paket-/Update-Szenarien
auf Windows und Linux mit temporären Testschlüsseln. Produktiv signierte
0.1.0- und 0.1.1-Pakete wurden laut Maintainer-Ausgaben nativ unter Windows und
Debian-WSL verifiziert. Das Linux-Paket bleibt für Ubuntu 24.04 x86_64 gebaut;
dies ist keine allgemeine Debian-Freigabe. Ein echter Online-Update-/Restore-
Durchlauf gegen ein veröffentlichtes Release ist noch nicht bestätigt.
`tools/smoke_app_update.py` bereitet diesen isolierten Test vor und führt ihn
mit `--run` aus; seine synthetischen Ablaufprüfungen ersetzen den realen Test nicht.
