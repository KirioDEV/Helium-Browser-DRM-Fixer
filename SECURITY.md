# Security model

This document explains the implemented protections, trust assumptions and
limitations. It is not a claim of an independent security audit. For usage,
see [README.md](README.md); for build/test instructions, see
[DEVELOPMENT.md](DEVELOPMENT.md).

## Scope and third-party software

The fixer installs and maintains Widevine files; it does not decrypt streaming
media, extract content keys or bypass DRM/HDCP checks. Repository and app-release
packages contain no Widevine binaries. Installation, package caching and backups
store them locally on the user's computer. No Widevine files are uploaded to
this project. See the [disclaimer](README.md#disclaimer) and
[third-party notices](THIRD_PARTY.md).

## Widevine download trust

- Google metadata and downloads use fixed endpoints. CDM download hosts are
  restricted to `dl.google.com` and `edgedl.me.gvt1.com`; GitHub is not a CDM source.
- Native HTTPS transports validate system certificates and hostnames, restrict
  redirects, bound response sizes and share a transfer deadline across redirects.
  Proxy use is not supported.
- DNS answers are restricted to public addresses and the validated address is
  pinned for the connection. Redirects undergo address/host checks again.
  Host headers and TLS SNI retain the authorized hostname.
- Metadata must contain consistent platform, component identity, hashes and
  package information. SHA-256 is checked before installation.
- CRX3 proofs are verified cryptographically. At least one valid signing key must
  derive Widevine component ID `oimompecagnajdejgnnjijobebaeigek`. An arbitrary
  self-signed CRX3 is insufficient. This is component-identity verification,
  not a claim of Web Store certification.
- Bounds include a 64 MiB package, 1 MiB metadata/CRX header, 256 ZIP entries and
  128 MiB declared expanded data. Only the manifest, matching CDM library and
  optional license are materialized after validation.
- Unsafe archive paths, links, special files, collisions and invalid native
  x86_64 PE/ELF headers are rejected. Libraries are inspected, never loaded.
- Cached packages are hash/signature-checked again before reuse. An extracted
  cache is not trusted. Explicit local Chrome sources have no CRX3 publisher
  guarantee; offline CRX3 validation cannot establish update freshness.

## Filesystem transactions

File and directory operations use no-follow handles, exclusive creation,
hardlink rejection, private permissions/ACLs and an exclusive installation lock.
Windows retains directory handles without delete sharing. Linux uses anchored
directory descriptors and relative operations such as `openat` and `renameat2`.
Rename destinations must not already exist; no overwriting fallback is used.

The configured Linux `HOME` is an explicit environment boundary. It is resolved
once to support system redirects such as `/home` to `/var/home`. Descendants
still undergo strict validation: configuration/profile/CDM/cache links are not
made acceptable by this resolution. The resolved destination is used throughout
an operation.

Staging and backups remain on the destination filesystem. Existing CDM files
are preserved before replacement. Journals and files are flushed across state
changes; Linux also synchronizes directories. Path bindings, journals and file
inventories are rechecked during install and restoration. Unexpected replacement
directories or modified backup contents are preserved rather than overwritten.

A pending transaction blocks another installation until recovery completes.
If an ancestor or managed directory moves, restore its original path mapping
before retrying recovery. The fixer does not automatically relocate unknown
replacement directories. Keep the private state directories while recovery is
needed. Backups are not automatically deleted.

## Signed fixer-app updates

App updates use stable releases from the fixed
`KirioDEV/Helium-Browser-DRM-Fixer` repository. A metadata check is not a package
signature check. Drafts, prereleases and ambiguous versions are rejected.

Packages use RSA-PKCS#1-v1.5 with SHA-256, a fixed signature context and an
embedded DER-SPKI RSA-3072/4096 public key. The public key comes from the build,
never from release metadata. Without a configured key, signed updates are
disabled. The signature covers the exact manifest bytes. Identity, repository,
platform, version, filename, sizes, hashes and every payload entry must match.

GUI and CLI identities/state directories are separate and fixed at compile time.
Windows self-updates require standalone MSVC builds; local MinGW builds can
inspect packages but cannot self-update. The Linux GUI replaces the complete
Type-2 AppImage rather than an executable inside its temporary mount.

A private copy of the old application acts as the helper. Parent identity and
executable hashes are bound, staged files are verified again, and replacement
waits for parent exit. The Linux GUI helper keeps checked private copies of its
bundled libraries so unmounting the old AppImage cannot remove dependencies.
Backup/journal validation protects restoration and missing-target recovery.

GUI updates restart the verified replacement. A failed handoff only restarts
the previous GUI if its bytes still match the expected old hash. CLI updates
do not automatically launch the replacement. `scheduled` only confirms handoff;
`installed` or `restored` confirms completion. See [APP_UPDATES.md](ui/APP_UPDATES.md).

## Build and signing boundaries

CI uses temporary test keys for fixtures. Production signing is restricted to
validated successful main-push builds and the release-signing environment.
Both platform inventories are checked before the encrypted key is materialized.
Temporary key files are outside upload directories and removed afterwards;
signatures are checked against the pinned project key. Publishing is manual.

The signing account/environment is trusted. A compromised authorized main
change, signing environment or private key can produce malicious signed updates.
App-update signatures are not Windows Authenticode signatures and do not remove
SmartScreen warnings.

## Limitations

- Root/administrator, a compromised OS or another process with the same user's
  authority can alter files and the program itself. This is outside the threat model.
- Held Linux descriptors do not lock files against the same user. Inventory
  checks and renames are not one atomic operation and cannot eliminate every race.
- Power-loss recovery depends on filesystem, device and flush behavior. There
  is no universal atomic swap of two non-empty directories.
- A free-space check does not reserve space; other processes can consume it.
- A local CDM check does not prove publisher integrity or streaming/HD support.
  Browser identity, HDCP and service policy can still prevent playback.
- Automated fixtures do not establish compatibility with every distribution,
  display setup or real streaming service. Flatpak/Snap, ARM64 and macOS are not
  supported. Windows system-DNS stall/rebinding behavior lacks the corresponding
  isolated real-system coverage available for Linux.

For reports, provide OS/browser/app versions, exact error text and reproducible
steps. Do not post credentials, cookies, license-server tokens or private keys.

## Implementation references

- [Chromium CRX3 schema](https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx3.proto)
- [Chromium CRX verifier](https://github.com/chromium/chromium/blob/main/components/crx_file/crx_verifier.cc)
- [WinHTTP options](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags)
- [libcurl address pinning](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html)
- [IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/)
