# Linux GUI: download and testing

The standalone AppImage is the graphical application. Its signed update packages
are separate from CLI packages; installing an app update requires confirmation.

## Download and start

Download the `.AppImage` and its `.sha256` file from the GitHub stable release.
The CI distribution baseline is **Ubuntu 24.04 x86_64**; older systems and other
distributions are not guaranteed compatible. A working X11 or Wayland desktop,
system fonts and a compatible graphics/input environment are required.

System redirects in the configured `HOME` path (for example `/home` pointing to
`/var/home`) are resolved before detection. The GUI displays the resolved target.
Symlinks inside the browser profile or at `WidevineCdm` remain unsupported and
are rejected. This path support does not establish distribution compatibility.

In the download directory (replace the example filename with the actual file):

```sh
sha256sum -c helium_drm_fixer_gui.AppImage.sha256
chmod u+x helium_drm_fixer_gui.AppImage
./helium_drm_fixer_gui.AppImage
```

The checksum detects file damage; it is not our app-update signature. Obtain both
files from the project's release page. If FUSE mounting is unavailable, start
with `--appimage-extract-and-run` instead. This extracts the app temporarily and
does not require root. Do not run the GUI with `sudo`.

The AppImage contains the GUI, embedded UI resources, bundled runtime libraries
and dependency notices. It does not contain Widevine or a browser. CLI self-update
commands do not update the GUI. Use Settings > Updates to install newer signed
stable GUI releases. Keep the original AppImage filename. For older builds and
recovery instructions, see [APP_UPDATES.md](APP_UPDATES.md).

## Real browser test

An existing `WidevineCdm` folder does not necessarily contain an active CDM.
If its `latest-component-updated-widevine-cdm` registration file is absent,
the app reports an incomplete local installation and permits **Install Widevine**.
Existing files are backed up and **Restore** returns that original state, even
if it was empty or incomplete. A genuine read/permission failure remains an
unavailable status; it is not treated as a repair diagnosis.

Use a current app build before testing Widevine. If an update fails, preserve
the AppImage and its recovery directories, record the exact error, and follow
[APP_UPDATES.md](APP_UPDATES.md) before retrying.

1. Record the distribution/version, desktop (X11/Wayland), Helium version and path.
2. Before installing anything, test a specific streaming title in Helium and note
   the result and any error message.
3. Close Helium completely. Start the GUI and select **Check**.
4. Confirm the target is the intended profile's `WidevineCdm` folder. With more
   than one profile/install, enter the exact folder and check again. The Linux
   target is profile-based, not a browser application/version directory.
5. Select **Install Widevine**, review the destination and confirm. Save the result.
6. Restart Helium and test the same title. Local validity does not guarantee
   streaming compatibility or HD playback.
7. Close Helium, select **Restore**, confirm, then select **Check**. Verify the
   previous Widevine version/state has returned. If Widevine was initially absent,
   the expected result is **Widevine is missing**.

Helium Flatpak/Snap installations are not supported. AppImage packaging of the
fixer does not establish compatibility with every browser packaging format or
streaming service; use the steps above to validate your own setup.

Report the OS/desktop/Helium versions, initial state, install result, playback
result and restore result. Include exact error text, but no account credentials,
cookies or streaming authorization tokens.

## Release packaging

After committing and pushing, wait for **Actions → Build GUI previews**, including
its signing job, to pass. Stable releases use the AppImage, checksum and signed
ZIP/manifest/signature from **signed-gui-app-release**. Include Windows GUI and
CLI assets from the same commit, following [APP_UPDATES.md](APP_UPDATES.md).
The `linux-gui-preview-ubuntu24.04-x86_64` artifact remains available for unsigned
preview testing. Publication is manual; prereleases are not offered by the updater.

The signed CLI release and its update assets remain separate from GUI assets.

## Project scope

This is an independent utility, not an official Google, Widevine or Helium app.
The AppImage contains no Widevine binaries. Installation stores Widevine locally;
the fixer does not decrypt media or extract DRM keys. See the full
[disclaimer](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer#disclaimer) and
[third-party notices](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/THIRD_PARTY.md).
