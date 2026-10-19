# Development guide

This guide covers building, testing and extending the current application.
Run commands from the repository root. User-facing instructions are in
[README.md](README.md) and [CLI.md](CLI.md).

## Requirements

- Windows 11 x64 or Linux x86_64; C++20 and CMake 3.24 or newer.
- MSVC with Visual Studio 2022 C++ tools for distributable Windows builds.
  CLion's MinGW toolchain is supported for local development.
- Ninja for the provided CMake presets.
- Python 3 and the OpenSSL executable for signing/package tests.
- Linux CLI: libcurl 7.85+, OpenSSL 3.0+, system CA certificates and development headers.
- GUI: Rust 1.92+ with a target matching the C++ compiler. The GUI workflow pins
  Rust 1.99.1. See [ui/README.md](ui/README.md) for GUI dependencies and commands.

CMake retrieves versioned, SHA-256-pinned source archives for nlohmann/json and
miniz, plus Slint and Corrosion when the GUI is enabled. Matching archives in
`.deps` are hash-checked too. GUI dependencies use the included Cargo lockfile.
The first build requires network access and more disk space than the final app.

## Build the CLI on Windows

From a Visual Studio developer PowerShell with CMake on PATH:

```powershell
$arguments = @(
    '-S', '.', '-B', 'build/msvc',
    '-G', 'Visual Studio 17 2022', '-A', 'x64',
    '-DBUILD_TESTING=ON',
    '-DFIXER_APP_UPDATE_PUBLIC_KEY:FILEPATH=keys/app-update-public.der'
)
cmake @arguments
cmake --build build/msvc --config Release --parallel 4
ctest --test-dir build/msvc -C Release --output-on-failure
```

Use `build/msvc/Release/helium_drm_fixer.exe --help` for a safe first launch.
Launching the CLI without arguments attempts installation.

Alternatively, open the repository as a CMake project in CLion, select its
MinGW toolchain and build `helium_drm_fixer`. The CLI development build needs
the runtime DLLs copied beside it; distributable standalone EXEs use MSVC.

## Build the CLI on Linux

Ubuntu 24.04 dependency example:

```sh
sudo apt install build-essential cmake ninja-build libcurl4-openssl-dev libssl-dev ca-certificates python3 openssl
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./build/debug/helium_drm_fixer --help
```

Other distributions need equivalent development packages. Installation requires
a filesystem supporting `renameat2(RENAME_NOREPLACE)`. Run the app as an
unprivileged user; build dependencies may require administrator privileges.

## Build the GUI

The GUI is opt-in with `FIXER_BUILD_GUI=ON`. Follow
[ui/README.md](ui/README.md) for MSVC, CLion/MinGW and Linux builds. It reuses
the same operation core and adds a separately compiled GUI app-updater identity.

## Architecture

| Area | Responsibility |
| --- | --- |
| `main.cpp`, `src/core.cpp` | CLI parsing, validation and command dispatch |
| `src/status.cpp` | Read-only installation inspection |
| `src/operation.cpp` | Install/restore orchestration and typed progress events |
| `src/platform.cpp` | OS-specific paths, process checks, crypto and file operations |
| `src/directory.cpp`, `src/install.cpp` | Anchored filesystem operations, transactions and recovery |
| `src/network.cpp`, `src/package.cpp` | Restricted HTTPS transport, Google metadata and CRX3/ZIP validation |
| `src/app_*.cpp` | Signed fixer-app packages, staging, helper handoff and executable recovery |
| `include/fixer.hpp`, `include/app_update.hpp` | Shared core interfaces |
| `ui/main.cpp`, `ui/app-window.slint` | Background GUI operations and declarative presentation |
| `tools/` | Build, packaging, signing, license collection and isolated validation tools |

`inspect_local(const Options&)` returns local status without printing or
downloading. `execute_operation(const Options&, const ProgressObserver&)`
performs active operations and emits typed phases. Observers execute on the
operation thread: keep them short, do not re-enter an operation, and copy GUI
events onto the UI thread. Observer exceptions do not change transaction results.

Use the existing cancellation flag and recovery rules. Cancellation is checked
before critical changes; recovery already in progress must finish safely.
Do not load CDM files as libraries to validate them, bypass no-follow checks,
or treat an unavailable installation as proof that it needs replacement.

## Tests and formatting

Use the checked-in Google-style `.clang-format` configuration for C++ changes.
Run the tests relevant to your change. The default suite covers CLI workflows,
installation detection, transaction security, process-crash recovery, signed
packages and native HTTPS failures. GUI-enabled builds add real-window smoke
tests and signed GUI-update tests.

```sh
cmake --preset sanitizers
cmake --build --preset sanitizers
ctest --preset sanitizers
```

The sanitizer preset is Linux-only. GUI tests require a graphical session or
Xvfb; `tools/build_linux_gui.sh` runs its selected tests under Xvfb.
`FIXER_REQUIRE_NETWORK_TESTS=ON` makes missing native network-test dependencies
a configuration error instead of allowing the group to be omitted.

Synthetic CDMs are inert PE/ELF headers, never loaded as libraries. Signed-update
tests generate temporary test keys. Do not use the production private key or a
real browser profile in automated fixtures. Real browser testing follows the
[Windows](ui/WINDOWS_TESTING.md) and [Linux](ui/LINUX_TESTING.md) guides.

Specialized filesystem/DNS tests require isolated containers, disposable volumes
or tmpfs mounts. Read their scripts before running them; ordinary development
does not require modifying host DNS, trust stores or real disks. Security
properties and remaining platform limits are documented in [SECURITY.md](SECURITY.md).

## Packaging and releases

For CLI installation staging:

```sh
cmake --preset release
cmake --build --preset release
cmake --install build/release --prefix build/package
```

`tools/package_app_release.py` wraps staged CLI files. The platform GUI packagers
wrap the completed Windows EXE or Linux AppImage and collect dependency notices.
Distributable Windows GUI builds must use MSVC. Keep Widevine binaries, private
keys, passphrases and local browser data out of source commits and release assets.

The CMake project version controls app versions. Each published replacement needs
a higher version; do not replace published binaries under the same version.
GUI and CLI use separate signed identities and artifact names. See
[APP_UPDATES.md](ui/APP_UPDATES.md) for the exact release inventory and signing
workflow. Downloaded trust keys must never replace the embedded public key.

Contributions should describe the resulting behavior, relevant validation and
compatibility limits. Update user/developer documentation when changing commands,
file layouts or trust boundaries. Preserve third-party license notices and the
required Slint About widget. The [disclaimer](README.md#disclaimer) and
[third-party notices](THIRD_PARTY.md) apply to source and release builds.
