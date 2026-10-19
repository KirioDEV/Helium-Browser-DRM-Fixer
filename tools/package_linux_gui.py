"""Build an isolated GUI AppImage preview, never an app-update package."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.request

from collect_gui_licenses import collect
from package_gui_release import gui_candidate

ROOT = Path(__file__).resolve().parent.parent
TOOLS = {
    "linuxdeploy": ("https://github.com/linuxdeploy/linuxdeploy/releases/download/1-alpha-20251107-1/linuxdeploy-x86_64.AppImage",
                    "c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d"),
    "appimagetool": ("https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage",
                     "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"),
    "runtime": ("https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64",
                "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"),
    "runtime-license": ("https://raw.githubusercontent.com/AppImage/type2-runtime/20251108/LICENSE",
                        "aa154fc9070614bbe7921f89db11efd1dba7a1f3a41685958110e2230f9c0ca1"),
}
DESKTOP = "io.github.KirioDEV.HeliumDRMFixer"


def run(*arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def download_tool(name, directory):
    url, expected = TOOLS[name]
    path = directory / name
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Invalid {name} download/hash")
    path.write_bytes(data)
    path.chmod(0o644 if name.endswith("license") else 0o755)
    return path


def extract_tool(tool, directory):
    directory.mkdir()
    run(tool, "--appimage-extract", cwd=directory, stdout=subprocess.DEVNULL)
    return directory / "squashfs-root/AppRun"


def library_notices(appdir, output):
    output.mkdir()
    libraries = subprocess.check_output(["/sbin/ldconfig", "-p"], text=True)
    inventory = []
    for library in sorted((appdir / "usr/lib").glob("*.so*")):
        if library.is_symlink() or not library.is_file():
            continue
        dynamic = subprocess.check_output(["readelf", "-d", str(library)], text=True)
        soname = re.search(r"\(SONAME\).*\[(.*?)\]", dynamic)
        lookup = soname[1] if soname else library.name
        matches = re.findall(r"^\s*" + re.escape(lookup) + r"\s+.*=>\s+(.*)$", libraries, re.M)
        if not matches:
            raise ValueError(f"Cannot attribute bundled library {library.name}")
        source = Path(matches[0]).resolve()
        candidates = [str(source)]
        if str(source).startswith("/usr/lib/"):
            candidates.append(str(source)[4:])
        owner = None
        for candidate in candidates:
            result = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True)
            if not result.returncode:
                owner = result.stdout.splitlines()[0].split(": ")[0]
                break
        if not owner:
            raise ValueError(f"Cannot identify package for {source}")
        notice = Path("/usr/share/doc") / owner.split(":")[0] / "copyright"
        shutil.copyfile(notice, output / (owner.replace(":", "_") + "-copyright"))
        fields = subprocess.check_output(["dpkg-query", "-W",
            "-f=${Version}\t${source:Package}\t${source:Version}", owner], text=True).split("\t")
        inventory.append({"library": library.name, "package": owner, "version": fields[0],
                          "source_package": fields[1], "source_version": fields[2]})
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    shutil.copytree("/usr/share/common-licenses", output / "common-licenses", symlinks=False)
    system = Path("/etc/os-release").read_text()
    source_lines = ["# Corresponding distribution sources", "",
                    "Exact source package versions for the bundled system libraries:", ""]
    for package in {item["package"]: item for item in inventory}.values():
        name, version = package["source_package"], package["source_version"]
        if 'ID=ubuntu' in system:
            url = f"https://launchpad.net/ubuntu/+source/{name}/{version}"
        else:
            url = f"https://sources.debian.org/src/{name}/{version}/"
        source_lines.append(f"- {name} {version}: {url}")
    (output / "SOURCES.md").write_text("\n".join(source_lines) + "\n", encoding="utf-8")


def package(build, output):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Build Linux x86_64 previews on native Linux/WSL")
    build = build.resolve(strict=True)
    gui_binary = (build / "helium_drm_fixer_gui").resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    version = subprocess.check_output([str(build / "helium_drm_fixer"), "--version"], text=True).strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid application version")
    distribution = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            distribution[key] = value.strip('"')
    baseline = distribution["ID"] + distribution["VERSION_ID"]
    if not re.fullmatch(r"[a-z0-9.]+", baseline):
        raise ValueError("Invalid build baseline")
    work = output / "work"
    work.mkdir()
    appdir = work / "AppDir"
    binary = appdir / "usr/bin/helium_drm_fixer_gui"
    binary.parent.mkdir(parents=True)
    shutil.copyfile(gui_binary, binary)
    binary.chmod(0o755)
    share = appdir / "usr/share/helium-drm-fixer"
    share.mkdir(parents=True)
    for name in ("README.md", "LICENSE", "SECURITY.md", "THIRD_PARTY.md"):
        shutil.copyfile(ROOT / name, share / name)
    shutil.copyfile(ROOT / "ui/LINUX_TESTING.md", share / "LINUX_TESTING.md")
    shutil.copyfile(ROOT / "ui/APP_UPDATES.md", share / "APP_UPDATES.md")
    collect(build / "_deps/slint-src/api/cpp/Cargo.toml", "x86_64-unknown-linux-gnu", share / "licenses/rust")
    for dependency, filename in (("json", "LICENSE.MIT"), ("miniz", "LICENSE")):
        shutil.copyfile(build / f"_deps/{dependency}-src/{filename}", share / "licenses" / f"{dependency}-LICENSE")
    tools = work / "tools"
    tools.mkdir()
    deploy = extract_tool(download_tool("linuxdeploy", tools), tools / "linuxdeploy-extracted")
    image_tool = extract_tool(download_tool("appimagetool", tools), tools / "appimagetool-extracted")
    runtime = download_tool("runtime", tools)
    shutil.copyfile(download_tool("runtime-license", tools), share / "licenses/AppImage-runtime-MIT.txt")
    # WSL imports the Windows PATH, including inaccessible system-profile paths.
    # Packaging tools only need Linux utilities and must not scan host programs.
    tool_environment = {**os.environ, "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}
    run(deploy, "--appdir", appdir, "--executable", binary,
        "--desktop-file", ROOT / f"ui/linux/{DESKTOP}.desktop",
        "--icon-file", ROOT / f"ui/linux/{DESKTOP}.svg",
        "--library", "/usr/lib/x86_64-linux-gnu/libxkbcommon.so.0",
        "--library", "/usr/lib/x86_64-linux-gnu/libxkbcommon-x11.so.0",
        "--library", "/usr/lib/x86_64-linux-gnu/libfontconfig.so.1", env=tool_environment)
    library_notices(appdir, share / "licenses/linux")
    image = output / "helium_drm_fixer_gui.AppImage"
    environment = {**tool_environment, "ARCH": "x86_64", "VERSION": version}
    run(image_tool, "--runtime-file", runtime, appdir, image, env=environment)
    image.chmod(0o755)
    (output / (image.name + ".sha256")).write_text(
        hashlib.sha256(image.read_bytes()).hexdigest() + "  " + image.name + "\n", encoding="ascii")
    shutil.copyfile(ROOT / "ui/LINUX_TESTING.md", output / "LINUX_TESTING.md")
    shutil.copyfile(ROOT / "ui/APP_UPDATES.md", output / "APP_UPDATES.md")
    if baseline == "ubuntu24.04":
        gui_candidate(build, image, version, "linux-x86_64-ubuntu24.04", output / "update-candidate")
    commit = os.environ.get("GITHUB_SHA")
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid source commit metadata")
    (output / "preview.json").write_text(json.dumps({
        "version": version, "source_commit": commit, "baseline": baseline,
        "architecture": "x86_64", "libc": platform.libc_ver(),
        "appimage": image.name, "self_update_package": False,
        "build_tools": {name: {"url": entry[0], "sha256": entry[1]}
                        for name, entry in TOOLS.items()}}, indent=2) + "\n", encoding="utf-8")
    print(f"GUI preview ready: {image}")
    print("GUI updates require signed stable release packages. No release was published.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New, nonexistent directory")
    args = parser.parse_args()
    package(args.build, args.output)
