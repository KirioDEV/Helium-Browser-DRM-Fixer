# Helium DRM Fixer

Helium DRM Fixer is a standalone maintenance utility for the **Helium browser**
on **Windows 11 x64** and **Linux x86_64**. It helps set up or repair the local
Widevine Content Decryption Module (CDM), which a browser uses to play protected
media from streaming services.

Use it to check whether Widevine is present and locally valid, install a verified
copy when needed, or restore the previous installation. The app backs up the
existing state before replacement and asks for confirmation in its desktop
interface. A separate command-line interface is available for terminal use.
Installing Widevine does not guarantee playback or HD support for every service.

**[Download for Windows (.exe)](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases/latest/download/helium_drm_fixer_gui.exe)**
· **[Download for Linux (.AppImage)](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases/latest/download/helium_drm_fixer_gui.AppImage)**
· [All releases, checksums and update packages](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases)

Independent community project. **Not affiliated with, endorsed by or sponsored
by Google, Widevine, imput or the Helium browser project.** Widevine is not
included in this repository or the distributed app packages. See the
[disclaimer](#disclaimer) below.

## Get started

1. Download the app and its matching `.sha256` file from the same release.
2. Verify the checksum using the [Windows guide](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/ui/WINDOWS_TESTING.md) or
   [Linux guide](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/ui/LINUX_TESTING.md).
3. Put the app in a writable folder owned by your user. Keep its original name.
4. Start it as your normal user, without administrator/root privileges.

Windows uses a portable `helium_drm_fixer_gui.exe`: no installer or adjacent
runtime DLLs are needed. Project and dependency license notices are embedded.
The EXE is not Authenticode-signed, so Windows may display a SmartScreen or
unknown-publisher warning. The app-update signatures do not remove that warning.

Linux uses `helium_drm_fixer_gui.AppImage`, built with an Ubuntu 24.04 baseline.
A compatible X11/Wayland desktop and system fonts are required. Other
distributions and older systems are not guaranteed compatible.

```sh
chmod u+x helium_drm_fixer_gui.AppImage
./helium_drm_fixer_gui.AppImage
```

If FUSE is unavailable, use:

```sh
./helium_drm_fixer_gui.AppImage --appimage-extract-and-run
```

## Install or restore Widevine

1. Launch Helium once to create its profile, then close Helium and Google Chrome
   completely.
2. Open the fixer and select **Check**. Review the detected **Widevine folder**.
   A custom path must identify the exact `WidevineCdm` folder.
3. Select **Install Widevine**, review the destination and confirm.
4. Restart Helium and test playback with your streaming service.
5. To undo the installation, close the browsers and select **Restore** for the
   same destination. Restore returns the previous Widevine state; if it was
   initially absent, it will be absent again.

The default source is Google's component-update service. The fixer verifies
the package identity, CRX3 signatures and SHA-256 before installation. The CLI
can also use an explicitly selected local Chrome source or offline CRX3 file;
local Chrome files do not receive a publisher-integrity guarantee.

Windows targets the browser's application/version directory. Linux targets a
profile-based Widevine directory. Flatpak/Snap Helium installations are not
supported. Redirects in the configured Linux `HOME` are resolved;
symlinks inside the profile or Widevine target remain rejected.

## App updates

Use **Settings > Updates > Check for updates**. When a newer
compatible release exists, the footer displays an underlined
**Update available - VERSION** link to that page. Confirm **Update and restart**
to download, verify and install it. The previous app version is retained for
recovery. The startup check only reads public GitHub release metadata.

Only higher-version, signed stable releases are offered automatically.
GUI and CLI packages cannot replace each
other. Widevine updates and fixer-app updates are separate operations.

[Update verification, recovery and maintainer release instructions](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/ui/APP_UPDATES.md).

## Compatibility and limitations

- Windows downloads target Windows 11 x64. Linux downloads use an Ubuntu 24.04
  baseline; an AppImage does not guarantee compatibility with every distribution.
- Browser packaging, filesystem permissions and the selected profile affect
  whether installation can proceed. Use the platform guides to check the target.
- A locally valid Widevine installation does not guarantee playback, HD/UHD,
  HDCP compatibility or acceptance by a particular streaming service. A service
  can impose requirements that this installer cannot change.

[Security model and limitations](SECURITY.md).

## CLI and development

[Windows CLI download](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases/latest/download/helium_drm_fixer.exe)
· [CLI commands, builds and technical reference](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/CLI.md)
· [Build and contribute](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/DEVELOPMENT.md)
· [GUI development and packaging](https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/blob/main/ui/README.md)
· [Third-party software and licenses](THIRD_PARTY.md)

The application core is C++20 and the desktop UI uses Slint. Published Windows
builds use MSVC; the Linux GUI is distributed as an AppImage. Build and signing
workflows prepare artifacts, while release publication remains manual.

## Disclaimer

This is an independent installation and maintenance utility, not an official
Google, Widevine or Helium product. Product names and trademarks belong to their
respective owners and are used only to identify compatible products.

**No Widevine binaries are hosted or bundled in this repository or its app
release packages.** When requested, the app downloads Widevine from Google's
servers or reads a source explicitly supplied by the user. It then stores
downloaded packages, installed files and backups **locally on the user's
computer** as required for caching, installation and recovery. It does not
upload those files to this project.

The fixer itself does not decrypt streaming media, extract content-decryption
keys, obtain streaming licenses, or patch Widevine to bypass DRM, HDCP,
subscriptions, regional restrictions or a service's playback policies. Its
package-signature checks verify downloaded files; they do not authorize access
to protected content. Media playback and content decryption are handled by the
browser and CDM, not by this utility.

Widevine remains proprietary software governed by its own applicable terms;
the project's MIT license does not grant rights to Widevine or other
third-party products. See [Google's Widevine notice](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/widevine/LICENSE)
and [third-party notices](THIRD_PARTY.md). Use only sources and services you
are authorized to use, and follow applicable licenses, service terms and law.

### Warranty and liability

The software is provided **as is**, without warranties, under [LICENSE](LICENSE).
To the extent permitted by applicable law, its authors and copyright holders
disclaim warranties and liability arising from use of the software, including
data loss, damaged installations, loss of access or service interruptions.
No compatibility, recovery, security, availability or HD/UHD playback guarantee
is made. Back up important data independently before changing an installation;
the app's backup/restore feature is not a substitute for your own backup.

**Mandatory law takes precedence.** Nothing in these notices excludes or limits
liability or rights that cannot lawfully be excluded or limited. This includes,
where applicable, liability for intentional misconduct, gross negligence,
negligently caused injury to life, body or health, mandatory product liability
and non-waivable consumer rights. The MIT license text remains unchanged.

Public availability of a download or a successful signature check does not
establish a license, authorization or endorsement from a third party. These
notices describe the project's scope; they are not a legal determination or
a guarantee of enforceability in any jurisdiction.
