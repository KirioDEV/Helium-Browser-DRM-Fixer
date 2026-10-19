# Windows GUI: download and testing

Download `helium_drm_fixer_gui.exe` and its `.sha256` file from the project's
stable release. The build targets **Windows 11 x64**. Only the EXE is needed to
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
page. The EXE is not Authenticode-signed, so Windows may show the unknown
publisher/SmartScreen prompt. It is separate from signed CLI update packages;
the CLI updater does not install this GUI. Use Settings > Updates to install
newer signed stable GUI releases. Keep the original EXE filename. For older
builds and recovery instructions, see [APP_UPDATES.md](APP_UPDATES.md).

`gui-notices.zip` is an optional readable copy of the notice archive embedded as
RCDATA resource 104. It contains project/Slint/Rust dependency licenses and the
Rust standard-library notices. It is not loaded or extracted at application startup.

## Practical test

1. Put the EXE alone into an empty folder and start it as your normal user.
2. Check that Explorer and the running window display the application icon.
3. Test Settings, theme selection, Updates, Help and About. Update checks belong
   to Settings > Updates; the local Widevine Check does not contact GitHub.
4. Before installing Widevine, note Helium's playback result for a specific title.
5. Close Helium and Chrome completely. Select **Check** and review the exact target.
6. Select **Install Widevine**, review and confirm the destination. Restart Helium
   and test the same title. Local validity does not guarantee streaming or HD.
7. Close the browsers, select **Restore**, confirm, and select **Check** again.
   The initial Widevine state/version should return; initially absent means missing.

## Release packaging

After committing and pushing, wait for **Actions > Build GUI previews**, including
its signing job, to pass. Stable releases use the EXE, checksum and signed
ZIP/manifest/signature from **signed-gui-app-release**, together with the Linux
GUI assets and the CLI artifacts for the same commit. Follow
[APP_UPDATES.md](APP_UPDATES.md) for the complete inventory and verification.
Publication remains manual. The separate `windows-gui-preview-x64` artifact is
for unsigned previews, including optional SVG and readable notice downloads.

Local MinGW builds are development builds. Published Windows builds use
MSVC; the packager rejects MinGW builds because their compiler-runtime notices
are not included by this MSVC packaging path.

## Project scope

This is an independent utility, not an official Google, Widevine or Helium app.
The download contains no Widevine binaries. Installation stores Widevine locally;
the fixer does not decrypt media or extract DRM keys. See the full
[disclaimer](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer#disclaimer) and
[third-party notices](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/THIRD_PARTY.md).
