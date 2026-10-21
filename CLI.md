# Command-line reference

The CLI checks and installs Widevine for Helium, restores previous installations,
and manages signed updates to the CLI itself. For the desktop app, see
[README.md](README.md). For source builds, see [DEVELOPMENT.md](DEVELOPMENT.md).
The [project disclaimer](README.md#disclaimer) applies to both interfaces.

## Start safely

Use `helium_drm_fixer.exe` on Windows and `helium_drm_fixer` on Linux.
Run as your normal user, not as administrator/root. Close Helium and Chrome
completely before installation or restoration.

**Starting the CLI without arguments attempts installation.** Use `--help`,
`--check` or `--dry-run` when you only want information.

```powershell
.\helium_drm_fixer.exe --help
.\helium_drm_fixer.exe --check
.\helium_drm_fixer.exe --dry-run
```

```sh
./helium_drm_fixer --check
./helium_drm_fixer --dry-run
```

`--check` and `--dry-run` are local, read-only operations: no downloads, cache
creation or log files. They do not establish streaming compatibility or the
publisher integrity of an existing installation.

## Select the destination

`--helium-path` means the **exact WidevineCdm directory**, not the browser's
application directory. Use the same destination when restoring.

```powershell
.\helium_drm_fixer.exe --helium-path 'C:\Users\NAME\AppData\Local\imput\Helium\Application\VERSION\WidevineCdm' --check
```

On Windows, `--helium-app-path` can instead select an application directory or
version directory. Detection selects the highest valid numeric browser version,
which is not necessarily the version currently running. It supports both
`helium.exe` and `chrome.exe`. This option cannot be combined with `--restore`
or an exact `--helium-path`; restore using the original exact destination.

```powershell
.\helium_drm_fixer.exe --helium-app-path 'C:\Users\NAME\AppData\Local\imput\Helium\Application' --dry-run
```

Linux uses the browser profile's `WidevineCdm` root, with version directories
and a hint file inside it. `XDG_CONFIG_HOME` is respected. The configured `HOME`
boundary is resolved before path validation; links inside the configuration,
profile or destination remain rejected. Multiple profiles require an explicit
destination. Flatpak/Snap browser installations are not supported.

## Install and choose a source

The default source is Google's component-update service. Installation verifies
package identity, CRX3 signatures and SHA-256 before staging and replacement.
There is no automatic fallback to a different trust source.

```sh
./helium_drm_fixer --source google
./helium_drm_fixer --source chrome --chrome-path /opt/google/chrome/WidevineCdm
./helium_drm_fixer --source package --package /path/to/widevine.crx3
```

Local Chrome files are trusted by your explicit selection and do not receive
a publisher-integrity guarantee. Offline CRX3 packages undergo signature and
identity checks, but an offline check does not establish their currentness.
`--force-download` bypasses the verified Google-package cache.

## Restore Widevine

```sh
./helium_drm_fixer --helium-path /absolute/profile/WidevineCdm --restore
```

The private `.helium-drm-fixer` directory beside the destination contains
ownership information, a lock, transaction journals and backups. Do not remove
it while recovery is needed. Restore returns the previous state, including
absence if Widevine was initially missing.

A pending transaction blocks another installation until recovery completes.
Modified backups, unexpected replacement directories and changed path bindings
are rejected rather than overwritten. Keep the original directory layout when
recovering an interrupted operation. Backups are not automatically purged.

## JSON and exit codes

```sh
./helium_drm_fixer --check --json
```

Schema version 1 provides `state`, `target`, `version`, `detail` and `exit_code`.
States are `missing`, `locally_invalid`, `locally_valid`, `recovery_required`
and `unavailable`. Unknown targets/versions are `null`. Local checks leave
`online_version_checked`, `publisher_integrity_verified` and
`streaming_compatibility_verified` false. Read failures are operational errors,
not an automatic recommendation to replace the CDM.

On Linux, an existing CDM root without its component-registration hint is
`locally_invalid`, not an access failure. Installation can repair that incomplete
state while preserving the original directory for restoration. Unreadable files
remain `unavailable` operational errors.

| Code | Meaning |
| --- | --- |
| 0 | Success or locally valid installation |
| 1 | Operational failure |
| 2 | Invalid options |
| 3 | Missing installation or no applicable update |
| 4 | Security validation failed |
| 5 | Recovery required |
| 130 | Cancelled |

## Update the CLI application

These commands update the fixer, not Widevine. They use stable releases from
`KirioDEV/Helium-Browser-DRM-Fixer`. CLI and GUI update packages are separate.

```sh
./helium_drm_fixer --check-app-update --json
./helium_drm_fixer --update-app
```

The first command reads release metadata without installing. The second
downloads and verifies a higher-version signed package, then schedules a
helper to replace the executable after the parent exits. `scheduled` only
confirms handoff; it does not confirm completed installation. The CLI does
not automatically launch the replacement program.

Keep the executable's original filename in a user-owned writable directory.
Windows self-updates require a standalone MSVC build. Local MinGW builds can
verify packages but cannot perform production self-updates.

Use the printed job path to check completion:

```sh
./helium_drm_fixer --app-update-status /absolute/job/path --json
```

Job states are `waiting_for_parent`, `applying`, `installed`, `restored` and
`failed`. Only `installed` or `restored` confirms completion. To restore the
previous CLI application, supply its exact absolute path:

```sh
./helium_drm_fixer --restore-app /absolute/path/helium_drm_fixer
```

On Windows the destination ends in `.exe`. If it is missing, use the retained
recovery helper printed during the update with the same `--restore-app` target.
Keep `.helium-app-update` and `.helium-app-update-jobs` beside the application.

## Verify an offline CLI release

Keep the ZIP, its `.manifest.json` and `.manifest.sig` together:

```sh
./helium_drm_fixer --verify-app-release /path/helium-drm-fixer-cpp-VERSION-linux-x86_64-ubuntu24.04.zip --json
```

Use the Windows package and `.exe` on Windows. Verification uses the embedded
public key, checks every payload file, and performs no installation or network
request. Same-version and older packages can be inspected; installation still
requires a higher version. The CLI verifier rejects GUI packages.

See [GUI update and release instructions](ui/APP_UPDATES.md) for publication,
and [SECURITY.md](SECURITY.md) for trust boundaries and limitations.
