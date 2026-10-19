# Third-party software and notices

The application is licensed under [LICENSE](LICENSE). Dependencies and Widevine
retain their own licenses; the project's license does not replace those terms.

| Component | Version/binding | License | Source |
| --- | --- | --- | --- |
| nlohmann/json | 3.12.0; pinned in CMakeLists.txt | MIT | https://github.com/nlohmann/json |
| miniz | 3.1.2; pinned in CMakeLists.txt | MIT | https://github.com/richgel999/miniz |
| Slint (GUI) | 1.18.1; pinned in cmake/SlintGui.cmake | Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0 | https://github.com/slint-ui/slint |
| Corrosion (GUI build) | 0.6.1; pinned in cmake/SlintGui.cmake | MIT | https://github.com/corrosion-rs/corrosion |
| libcurl (Linux) | Distribution package, 7.85+ | curl license | https://curl.se/docs/copyright.html |
| OpenSSL (Linux) | Distribution package, 3.0+ | Apache-2.0 | https://www.openssl.org/source/license.html |
| MinGW runtimes (development builds) | Selected compiler toolchain | Applicable runtime licenses and exceptions | https://www.mingw-w64.org/ |

## Distributed notices

Windows uses WinHTTP, Crypt32, BCrypt and other system libraries supplied by the
OS. Published MSVC builds link the compiler runtime statically. The Linux CLI
uses system libraries dynamically; the GUI AppImage bundles selected libraries.

CMake installs README, security/third-party notices, the project license and
miniz/nlohmann-json license texts under `share/helium-drm-fixer`. Windows EXEs
embed the corresponding base licenses. GUI packaging adds Slint, the selected
Cargo dependency graph and Rust standard-library notices.

`tools/collect_gui_licenses.py` collects GUI notices. Missing crate license files
are supplemented from fixed upstream revisions with SHA-256 hashes recorded in
`tools/gui-license-supplements.json`. Original embedded notices are retained;
standard license texts are identified as such, without invented copyright claims.
Bundled Linux libraries include distribution copyright/license information,
source package versions and source references. The AppImage runtime has its own
MIT notice. Build tools pinned in `tools/package_linux_gui.py` are not distributed.

The Windows GUI embeds its additional notice ZIP in RCDATA resource 104.
`gui-notices.zip`, when offered separately, is a byte-identical readable copy
and is not needed at runtime. MinGW development builds are not accepted by the
MSVC distribution packager. Anyone distributing different toolchain/runtime
combinations must satisfy those components' applicable terms.

Preserve Slint's required `AboutSlint` widget in Settings > About and its
[license text](https://github.com/slint-ui/slint/blob/v1.18.1/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md).
GUI and CLI have separate signed packages; neither package contains Widevine.

## Widevine and project affiliation

Widevine is proprietary and is not hosted in this repository or bundled in app
releases. The fixer downloads it from Google's servers or reads a source selected
by the user. Installation, caching and backups store files locally on the user's
computer, without uploading them to this project. Any supplied Widevine license
text is preserved during installation.

The project license grants no rights to Widevine. Its applicable terms remain
those of its rights holder; see [Google's Widevine notice](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/widevine/LICENSE).
The fixer does not decrypt streaming media, extract content keys or modify
Widevine to bypass DRM/HDCP checks or a service's access policies.

This project is not affiliated with, endorsed by or sponsored by Google,
Widevine, imput or the Helium browser project. Product names and trademarks
identify compatible products and belong to their respective owners. The
[disclaimer](README.md#disclaimer) explains the scope and does not grant
third-party permissions or constitute a legal determination.
