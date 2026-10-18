param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$clion = Join-Path $env:LOCALAPPDATA 'Programs/CLion'
$cmake = Join-Path $clion 'bin/cmake/win/x64/bin/cmake.exe'
$ctest = Join-Path $clion 'bin/cmake/win/x64/bin/ctest.exe'
$ninja = Join-Path $clion 'bin/ninja/win/x64/ninja.exe'
$compilerDirectory = Join-Path $clion 'bin/mingw/bin'
foreach ($tool in @($cmake, $ctest, $ninja, (Join-Path $compilerDirectory 'g++.exe'))) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "CLion-Werkzeug fehlt: $tool" }
}

$savedEnvironment = @{}
foreach ($name in @('PATH', 'RUSTUP_HOME', 'CARGO_HOME', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_RELEASE_DEBUG')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location -LiteralPath $repository
try {
    $localCargo = Join-Path $repository 'build/ui-tools/cargo'
    if (Test-Path -LiteralPath (Join-Path $localCargo 'bin/cargo.exe')) {
        $env:CARGO_HOME = $localCargo
        $env:RUSTUP_HOME = Join-Path $repository 'build/ui-tools/rustup'
        $env:PATH = "$(Join-Path $localCargo 'bin');$env:PATH"
    }
    $env:PATH = "$compilerDirectory;$env:PATH"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'Rust fehlt. Rust mit GNU-Windows-Toolchain installieren; siehe ui/README.md.'
    }
    $env:CARGO_BUILD_JOBS = '4'
    $env:CARGO_PROFILE_RELEASE_DEBUG = '0'
    & $cmake -S . -B build/gui -G Ninja "-DCMAKE_BUILD_TYPE=$Configuration" `
        "-DCMAKE_MAKE_PROGRAM:FILEPATH=$ninja" `
        "-DCMAKE_C_COMPILER:FILEPATH=$(Join-Path $compilerDirectory 'gcc.exe')" `
        "-DCMAKE_CXX_COMPILER:FILEPATH=$(Join-Path $compilerDirectory 'g++.exe')" `
        '-DRust_CARGO_TARGET=x86_64-pc-windows-gnu' `
        -DFIXER_BUILD_GUI=ON -DBUILD_TESTING=ON `
        '-DFIXER_APP_UPDATE_PUBLIC_KEY:FILEPATH=keys/app-update-public.der'
    if ($LASTEXITCODE -ne 0) { throw 'GUI-Konfiguration fehlgeschlagen.' }
    & $cmake --build build/gui --target helium_drm_fixer_gui --parallel 4
    if ($LASTEXITCODE -ne 0) { throw 'GUI-Build fehlgeschlagen.' }
    if ($Test) {
        & $ctest --test-dir build/gui -R '^gui_readonly_startup$' --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw 'GUI-Test fehlgeschlagen.' }
    }
    Write-Host 'GUI: build/gui/helium_drm_fixer_gui.exe'
}
finally {
    Pop-Location
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
