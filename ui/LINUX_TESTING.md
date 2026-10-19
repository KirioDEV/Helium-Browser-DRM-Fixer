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
commands do not update the GUI. Version 0.1.2 uses footer update controls;
since 0.1.3, Settings > Updates installs newer signed stable GUI releases.
Keep the original AppImage filename for this.
The old 0.1.1 preview needs one manual upgrade first. See [APP_UPDATES.md](APP_UPDATES.md).

## Real browser test

The maintainer reports the 0.1.3 release and app-update test complete; the real
Bazzite/Helium DRM test remains pending. A tester starting on 0.1.2 should first
update to 0.1.3 and confirm the new version before the steps below. Version 0.1.2
uses footer update controls; 0.1.3 uses Settings > Updates. If the old updater
rejects `/home`, preserve the old AppImage and record its exact path/error before
trying to launch it from the resolved physical path.

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

Helium Flatpak/Snap installations are not supported. The native/AppImage Helium
browser itself still needs a real integration test. AppImage packaging of the
fixer does not establish compatibility with every browser packaging format.

Report the OS/desktop/Helium versions, initial state, install result, playback
result and restore result. Include exact error text, but no account credentials,
cookies or streaming authorization tokens.

## Maintainer handoff

After committing and pushing, wait for **Actions → Build GUI previews**, including
its signing job, to pass. Stable releases use the AppImage, checksum and signed
ZIP/manifest/signature from **signed-gui-app-release**. Include Windows GUI and
CLI assets from the same commit, following [APP_UPDATES.md](APP_UPDATES.md).
The `linux-gui-preview-ubuntu24.04-x86_64` artifact remains available for unsigned
preview testing. Publication is manual; prereleases are not offered by the updater.

The existing signed CLI release and its update assets remain separate. An actual
GUI-based streaming test on Linux remains pending until a tester reports it.

## Project scope

This is an independent utility, not an official Google, Widevine or Helium app.
The AppImage contains no Widevine binaries. Installation stores Widevine locally;
the fixer does not decrypt media or extract DRM keys. See the full
[disclaimer](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer#disclaimer) and
[third-party notices](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/THIRD_PARTY.md).
