# Signed GUI app updates

The GUI checks the latest stable release in `KirioDEV/Helium-Browser-DRM-Fixer`
after its initial local Widevine inspection. **Settings > Updates** provides
**Check for updates**. This request reads public GitHub metadata; it does not download an app
package or change Widevine. Failed/offline checks leave the app usable.

If a newer compatible GUI package, manifest and signature are published, the
footer shows a highlighted, underlined **Update available - VERSION** link.
It opens **Settings > Updates**, where **Update to VERSION** leads to the
**Update and restart** confirmation. Update status and progress stay on that page.
The app downloads the manifest/signature, verifies the embedded RSA public key,
then checks the ZIP and every payload file before scheduling replacement.
The helper pins the parent process, waits for it to exit, verifies the staged
files again, replaces the executable and restarts the GUI. The previous version
and a transaction journal remain in a private sibling directory.

Updates use a distinct signed `helium-drm-fixer-gui` identity. CLI packages use
`helium-drm-fixer-cpp` and cannot replace the GUI. Both use the existing pinned
public key and signature algorithm. Downloaded metadata never supplies trust.
Prereleases are ignored by the automatic updater. A release title alone cannot
make a package eligible; it needs a higher three-component application version,
matching asset names, manifest and signature.

## First update-capable version

Version **0.1.2** introduced GUI self-updates. The old 0.1.1 GUI preview needs
one manual upgrade to 0.1.2 or newer. Later signed stable versions can be
installed from the app, using Settings > Updates since 0.1.3.
Do not overwrite an existing release with different binaries using the same
version. Increase the project version for each new update.

Version 0.1.2 uses its original footer check/update controls. Since 0.1.3, these
controls live in Settings > Updates and the footer update link opens that page.
The maintainer reports the 0.1.3 release and app-update test complete. Real
Bazzite/Helium Widevine installation and streaming testing remain pending.

## Supported files and recovery

- Windows: MSVC standalone `helium_drm_fixer_gui.exe`, without adjacent DLLs.
- Linux: the complete Ubuntu-24.04-baseline `helium_drm_fixer_gui.AppImage`.
  The updater replaces the outer AppImage, not the executable in its temporary
  mount/extraction directory. Restart uses extraction mode and does not need FUSE.
  The helper keeps a bounded, read-back-checked private copy of the current
  bundle's libraries, so unmounting the old AppImage cannot remove its dependencies.
- Keep the original filename and use a writable directory owned by your user.
  Local MinGW builds and unpackaged native Linux GUI binaries do not self-update.
- The app update changes only the app. The main **Restore** button continues to
  restore Widevine, not the application.
- A failed transaction preserves/restores the previous bytes. After parent exit,
  the helper restarts the previous app only if its hash matches the expected old
  version. Unknown files are preserved for manual recovery. Staged files and
  helper status are retained for diagnosis.

To explicitly return to the previous application version, close the GUI and run:

```powershell
& './helium_drm_fixer_gui.exe' --restore-app
```

```sh
./helium_drm_fixer_gui.AppImage --appimage-extract-and-run --restore-app
```

The old helper and state live in `.helium-gui-app-update-jobs` and
`.helium-gui-app-update` beside the executable. Keep them while recovery is needed.
If the original program file is missing, the retained Windows helper (or complete
Linux backup AppImage) also accepts `--restore-app ABSOLUTE_ORIGINAL_PATH`.
Use the actual original canonical filename. Recovery validates the private
journal and known backup before restoring it; it preserves unexpected files.
To opt out of the automatic startup metadata request, set
`HELIUM_FIXER_DISABLE_UPDATE_CHECK=1`; the manual check in Settings still works.

## Build, signing and publication

`Build GUI previews` produces separate unsigned candidates after packaging the
tested Windows EXE and Linux AppImage. A successful main-push run calls
`Sign GUI app release` using the existing `release-signing` environment and its
two signing secrets. The signer checks the exact source commit, workflow identity
and successful Windows/Linux jobs before validating both complete candidates.
Only then is the encrypted private key temporarily materialized. It is not copied
to outputs. GUI and CLI signing operate on different build runs/artifact names.

Download **signed-gui-app-release** after signing succeeds. Extract the outer
artifact ZIP and upload these files to the matching stable release, e.g. `v0.1.3`:

- `helium-drm-fixer-gui-0.1.3-windows-x64.zip`
- The Windows ZIP's `.manifest.json` and `.manifest.sig`
- `helium-drm-fixer-gui-0.1.3-linux-x86_64-ubuntu24.04.zip`
- The Linux ZIP's `.manifest.json` and `.manifest.sig`
- `helium_drm_fixer_gui.exe` and its `.sha256`
- `helium_drm_fixer_gui.AppImage` and its `.sha256`

The exported standalone binaries are byte-identical to the signed ZIP payloads.
Publication remains manual; the workflow has no release-write permission. A
pre-release is suitable for testing but will not be offered by automatic updates.
For this project's stable releases, upload the separate CLI signed assets from
`signed-app-release` for the same source commit as well. This preserves the
existing CLI updater and README download links. Both build/signing workflows
must be successful. Copy/adapt the GUI release notes to put the Windows GUI
download first.

The GUI inventory contains ten files. The CLI artifact adds these seven files,
for **17 release assets in total** (substitute the actual release version):

```text
helium_drm_fixer.exe
helium-drm-fixer-cpp-0.1.3-windows-x64.zip
helium-drm-fixer-cpp-0.1.3-windows-x64.zip.manifest.json
helium-drm-fixer-cpp-0.1.3-windows-x64.zip.manifest.sig
helium-drm-fixer-cpp-0.1.3-linux-x86_64-ubuntu24.04.zip
helium-drm-fixer-cpp-0.1.3-linux-x86_64-ubuntu24.04.zip.manifest.json
helium-drm-fixer-cpp-0.1.3-linux-x86_64-ubuntu24.04.zip.manifest.sig
```

The CLI signer currently exports no separate CLI-EXE checksum. Use the GUI
`release-notes.md` as release-description text, not as an extra required asset.
Attach individual files, not the outer GitHub artifact ZIPs. Stable releases
must not be marked as prereleases, and must be selected as latest to be offered
by the updater. Keep previous releases available for update/recovery tests.

Before publication, the locally trusted GUI can verify a signed GUI ZIP offline
with `--verify-app-release PATH_TO_GUI_ZIP`. It reports JSON and does not install
anything. The CLI verifier deliberately rejects GUI packages.

## Automated checks

`gui_signed_updates` uses ephemeral test keys to exercise GUI/CLI separation,
signature/ZIP tampering, incomplete/prerelease metadata, post-handoff mutation,
parent-exit gating, exact replacement bytes, GUI restart and application restore,
including recovery when the target executable is missing.
Linux CI also runs that backend inside a real AppImage with bundled libraries
and separate inner/outer executable paths. These fixtures are never distributed.
Tests do not use the production private key or modify a real browser installation.
