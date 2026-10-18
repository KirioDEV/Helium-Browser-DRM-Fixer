#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"
if [[ -x "$repository/build/linux-ui-tools/cargo/bin/cargo" ]]; then
    export CARGO_HOME="$repository/build/linux-ui-tools/cargo"
    export RUSTUP_HOME="$repository/build/linux-ui-tools/rustup"
    export PATH="$CARGO_HOME/bin:$PATH"
fi
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
export CARGO_PROFILE_RELEASE_DEBUG=0
build_directory=${1:-build/linux-gui}
cmake -S . -B "$build_directory" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON -DFIXER_BUILD_GUI=ON \
    -DFIXER_APP_UPDATE_PUBLIC_KEY:FILEPATH="$repository/keys/app-update-public.der"
cmake --build "$build_directory" --target helium_drm_fixer_gui helium_drm_fixer --parallel 4
env -u WAYLAND_DISPLAY SLINT_BACKEND=winit-software \
    xvfb-run -a ctest --test-dir "$build_directory" -R '^gui_readonly_startup$' --output-on-failure
