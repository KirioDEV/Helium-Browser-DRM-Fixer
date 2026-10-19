"""Prepare a standalone MSVC GUI preview with embedded dependency notices."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from collect_gui_licenses import collect
from windows_gui_resources import embed_notices, verify_notices
from package_gui_release import gui_candidate

ROOT = Path(__file__).resolve().parent.parent
ICON = "io.github.KirioDEV.HeliumDRMFixer.svg"


def notice_archive(build, directory):
    for name in ("README.md", "LICENSE", "SECURITY.md", "THIRD_PARTY.md"):
        shutil.copyfile(ROOT / name, directory / name)
    shutil.copyfile(ROOT / f"ui/linux/{ICON}", directory / ICON)
    collect(build / "_deps/slint-src/api/cpp/Cargo.toml", "x86_64-pc-windows-msvc",
            directory / "licenses/rust")
    for dependency, filename in (("json", "LICENSE.MIT"), ("miniz", "LICENSE")):
        shutil.copyfile(build / f"_deps/{dependency}-src/{filename}",
                        directory / "licenses" / f"{dependency}-LICENSE")
    archive = directory.parent / "gui-notices.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(directory).as_posix())
    return archive.read_bytes()


def package(build, output):
    if os.name != "nt":
        raise ValueError("Package the Windows GUI on Windows")
    build = build.resolve(strict=True)
    compilers = list((build / "CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
    if not compilers or any('set(CMAKE_CXX_COMPILER_ID "MSVC")' not in path.read_text(encoding="utf-8")
                            for path in compilers):
        raise ValueError("Release previews require MSVC; MinGW runtime notices are not packaged")
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    version = re.search(r"^CMAKE_PROJECT_VERSION:STATIC=(\d+\.\d+\.\d+)$", cache, re.M)
    if not version:
        raise ValueError("Missing build version")
    version = version[1]
    binary = (build / "Release/helium_drm_fixer_gui.exe").resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    executable = output / "helium_drm_fixer_gui.exe"
    shutil.copyfile(binary, executable)
    with tempfile.TemporaryDirectory(prefix="gui-notices-", dir=build) as temporary:
        directory = Path(temporary) / "notices"
        directory.mkdir()
        data = notice_archive(build, directory)
        embed_notices(executable, data)
        verify_notices(executable)
        shutil.copyfile(Path(temporary) / "gui-notices.zip", output / "gui-notices.zip")
    (output / (executable.name + ".sha256")).write_text(
        hashlib.sha256(executable.read_bytes()).hexdigest() + "  " + executable.name + "\n", encoding="ascii")
    shutil.copyfile(ROOT / f"ui/linux/{ICON}", output / ICON)
    shutil.copyfile(ROOT / "ui/WINDOWS_TESTING.md", output / "WINDOWS_TESTING.md")
    shutil.copyfile(ROOT / "ui/APP_UPDATES.md", output / "APP_UPDATES.md")
    gui_candidate(build, executable, version, "windows-x64", output / "update-candidate")
    commit = os.environ.get("GITHUB_SHA")
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid source commit metadata")
    (output / "preview.json").write_text(json.dumps({
        "version": version, "source_commit": commit, "platform": "windows-x64",
        "compiler": "MSVC", "self_update_package": False, "authenticode_signed": False,
        "executable": executable.name, "notice_resource": 104,
        "embedded_notices_sha256": hashlib.sha256(data).hexdigest()}, indent=2) + "\n", encoding="utf-8")
    print(f"Standalone GUI preview ready: {executable}")
    print("Unsigned GUI update candidate prepared. No release was published.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New, nonexistent directory")
    args = parser.parse_args()
    package(args.build, args.output)
