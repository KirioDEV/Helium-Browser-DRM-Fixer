# GUI development and packaging

The desktop interface uses Slint 1.18.1 with the C++20 operation core. It provides
local inspection, confirmed Widevine installation/restoration, cancellation and
signed app updates. See [README.md](../README.md) for usage and
[DEVELOPMENT.md](../DEVELOPMENT.md) for the shared architecture and CLI build.

## Toolchains

Enable `FIXER_BUILD_GUI=ON`; it is off by default. Install Rust 1.92 or newer
with the target matching your C++ compiler: `x86_64-pc-windows-msvc` for MSVC,
`x86_64-pc-windows-gnu` for MinGW, or the native Linux x86_64 target. The GUI
workflow pins Rust 1.99.1. CMake requires version 3.24 or newer.

Slint/Corrosion sources are versioned and SHA-256-pinned in
`cmake/SlintGui.cmake`; Cargo uses the lockfile. The first build downloads and
compiles dependencies. Subsequent builds reuse local build artifacts.

## Windows with MSVC

Use a Visual Studio developer PowerShell and the MSVC Rust target:

```powershell
$arguments = @(
    '-S', '.', '-B', 'build/gui-msvc',
    '-G', 'Visual Studio 17 2022', '-A', 'x64',
    '-DFIXER_BUILD_GUI=ON', '-DBUILD_TESTING=ON',
    '-DRust_TOOLCHAIN:STRING=1.99.1-x86_64-pc-windows-msvc',
    '-DFIXER_APP_UPDATE_PUBLIC_KEY:FILEPATH=keys/app-update-public.der'
)
cmake @arguments
cmake --build build/gui-msvc --config Release --parallel 4
ctest --test-dir build/gui-msvc -C Release -R '^gui_' --output-on-failure
python tools/package_windows_gui.py --build build/gui-msvc --output build/windows-gui-package
```

The output directory must not already exist. Published EXEs use static MSVC and
Slint runtimes. Windows system DLLs remain OS dependencies. Project, Slint, Rust
and dependency notices are embedded; adjacent runtime DLLs are not required.

## Windows with CLion/MinGW

With CLion's standard installation and a GNU Rust toolchain available:

```powershell
.\tools\build_gui.ps1 -Test
.\build\gui\helium_drm_fixer_gui.exe
```

The helper uses CLion's bundled CMake, Ninja and compiler. If present, it uses
project-local Rust tools in `build/ui-tools`; otherwise Rust must be on PATH.
Temporary environment changes are restored afterwards. The static MinGW GUI
uses UCRT consistently; do not mix MSVCRT/UCRT allocators. These local builds
cannot self-update and are not accepted by the MSVC distribution packager.

## Linux

In addition to CLI dependencies, install Rust, Fontconfig, X11/Wayland development
packages, XKB/input headers, Xvfb, xauth, fonts, patchelf and squashfs-tools.
The exact Ubuntu package list is in `.github/workflows/gui-preview.yml`.

```sh
bash tools/build_linux_gui.sh
python3 tools/package_linux_gui.py --build build/linux-gui --output build/linux-gui-package
```

The build helper runs selected tests under Xvfb. Packaging requires a fresh
output directory and retrieves hash-pinned AppImage tools. It bundles runtime
libraries and their notices, then creates an AppImage and checksum. Production
Linux update candidates use the Ubuntu 24.04 distribution baseline; packages
built on another distribution must not be mislabeled as Ubuntu candidates.

## Extending the UI

- `app-window.slint` defines the fixed-size English interface, themes, navigation
  and confirmations. Settings contains Updates, Help and About.
- `main.cpp` runs operations on a worker and posts results to Slint's event loop
  using weak component handles. Never access UI properties from the worker.
- Local checks preserve the last status while reading. Update checks display
  progress for at least one second without blocking the UI thread.
- The footer update link opens Settings > Updates; installation requires a
  separate confirmation. App updates and Widevine Restore are distinct actions.
- `tests/gui_smoke.py` and `tests/gui_interaction.ps1` exercise isolated startup
  and interactions. `tests/gui_updates.py` covers signed helper/recovery behavior.
- The SVG in `linux/` is the shared icon source. See
  [windows/README.md](windows/README.md) before regenerating the ICO.

The GUI updater is compiled with a fixed identity separate from the CLI. Preserve
this distinction when changing linking or packaging. Linux replaces the complete
outer AppImage; the helper retains private library copies across unmounting.

## Notices and release outputs

Slint is used under the Royalty-free Desktop, Mobile, and Web Applications
License 2.0. Preserve the required `AboutSlint` widget in Settings > About and
the dependency notices described in [THIRD_PARTY.md](../THIRD_PARTY.md).

The workflow named **Build GUI previews** also prepares signed release artifacts
after successful main-push builds. Use **signed-gui-app-release** for stable
distribution, not the unsigned preview artifacts. Publication remains manual.
Follow [APP_UPDATES.md](APP_UPDATES.md) for signing and release instructions.
