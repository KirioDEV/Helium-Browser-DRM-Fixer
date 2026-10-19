# Linux GUI preview

This is a separate preview of the graphical application. It is not an update
package for the existing CLI and does not install itself automatically.

## Download and start

Download the `.AppImage` and its `.sha256` file from the GitHub preview release.
The CI distribution baseline is **Ubuntu 24.04 x86_64**; older systems and other
distributions are not guaranteed compatible. A working X11 or Wayland desktop,
system fonts and a compatible graphics/input environment are required.

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
commands do not update the GUI. From version 0.1.2 Settings > Updates can install
newer signed stable GUI releases. Keep the original AppImage filename for this.
The old 0.1.1 preview needs one manual upgrade first. See [APP_UPDATES.md](APP_UPDATES.md).

## Real browser test

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

After committing and pushing, open **Actions → Build GUI previews**. Download
`linux-gui-preview-ubuntu24.04-x86_64` after the workflow is green. Extract the
outer GitHub artifact ZIP, then upload the inner AppImage, checksum and this guide
to a GitHub **pre-release** with matching source commit in its description.
The workflow builds and checks packages; it does not publish a release.

The existing signed CLI release and its update assets remain separate. An actual
GUI-based streaming test on Linux remains pending until a tester reports it.
