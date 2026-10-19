# Windows GUI preview

Download `helium_drm_fixer_gui.exe` and its `.sha256` file from the project's
preview release. The build targets **Windows 11 x64**. Only the EXE is needed to
run: compiler libraries, Slint UI resources, the application icon and dependency
notices are embedded. No installer or adjacent DLLs are needed.

The supplied SVG is the same icon used on Linux. Windows Explorer uses a
multi-resolution ICO generated from that SVG; the running window uses the SVG.
The SVG is an optional download, not a runtime requirement.

## Verify and start

In PowerShell, in the download directory:

```powershell
$expected = ((Get-Content './helium_drm_fixer_gui.exe.sha256').Split(' ')[0]).ToLowerInvariant()
$actual = (Get-FileHash './helium_drm_fixer_gui.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'Checksum mismatch' }
& './helium_drm_fixer_gui.exe'
```

The checksum detects file damage; obtain both files from the project's release
page. This preview is not Authenticode-signed, so Windows may show the unknown
publisher/SmartScreen prompt. It is separate from signed CLI update packages;
the CLI updater does not install this GUI. From version 0.1.2 Settings > Updates can install
newer signed stable GUI releases. Keep the original EXE filename. The old 0.1.1
GUI needs one manual upgrade first. See [APP_UPDATES.md](APP_UPDATES.md).

`gui-notices.zip` is an optional readable copy of the notice archive embedded as
RCDATA resource 104. It contains project/Slint/Rust dependency licenses and the
Rust standard-library notices. It is not loaded or extracted at application startup.

## Practical test

1. Put the EXE alone into an empty folder and start it as your normal user.
2. Check that Explorer and the running window display the application icon.
3. Test Settings, theme selection, Help and About.
4. Before installing Widevine, note Helium's playback result for a specific title.
5. Close Helium and Chrome completely. Select **Check** and review the exact target.
6. Select **Install Widevine**, review and confirm the destination. Restart Helium
   and test the same title. Local validity does not guarantee streaming or HD.
7. Close the browsers, select **Restore**, confirm, and select **Check** again.
   The initial Widevine state/version should return; initially absent means missing.

## Maintainer handoff

After committing and pushing, wait for **Actions > Build GUI previews** to pass.
Download `windows-gui-preview-x64`, extract the outer artifact ZIP and attach
the EXE, checksum, SVG, `gui-notices.zip` and this guide to a GitHub **pre-release**.
Record its source commit from `preview.json`. The workflow builds and tests the
preview but does not publish a release or replace stable CLI downloads.

Local MinGW builds are development builds. Downloadable Windows previews use
MSVC; the packager rejects MinGW builds because their compiler-runtime notices
are not included by this MSVC packaging path.
