"""Collect notices from Slint's locked, target-specific Rust dependency graph."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request


def collect(manifest, target, output):
    manifest = manifest.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(manifest), "--filter-platform", target,
        "--no-default-features", "--features",
        "backend-winit,renderer-software,accessibility,std"], text=True, encoding="utf-8"))
    packages = {package["id"]: package for package in metadata["packages"]}
    # metadata unifies features across the whole Slint workspace. Use tree's
    # selected package graph to avoid attributing unused Qt/Skia dependencies.
    tree = subprocess.check_output([
        "cargo", "tree", "--locked", "--manifest-path", str(manifest),
        "--target", target, "-p", "slint-cpp", "--no-default-features",
        "--features", "backend-winit,renderer-software,accessibility,std",
        "--edges", "normal,build", "--prefix", "none", "--format", "{p}"], text=True, encoding="utf-8")
    selected_names = {tuple(line.split()[:2]) for line in tree.splitlines()}
    selected = {identifier for identifier, package in packages.items()
                if (package["name"], "v" + package["version"]) in selected_names}
    print(f"Collecting notices for {len(selected)} selected Rust packages", flush=True)
    supplements = json.loads(Path(__file__).with_name("gui-license-supplements.json").read_text(encoding="utf-8"))
    inventory = []
    download_cache = {}
    workspace = Path(metadata["workspace_root"])
    for identifier in sorted(selected):
        package = packages[identifier]
        directory = Path(package["manifest_path"]).parent
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", package["name"] + "-" + package["version"])
        destination = output / name
        destination.mkdir()
        notices = set()
        if package.get("license_file"):
            notices.add(directory / package["license_file"])
        for base in (directory, directory / "licenses", directory / "LICENSES"):
            if base.is_dir():
                for path in base.iterdir():
                    if path.is_file() and path.name.upper().startswith(
                            ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")):
                        notices.add(path)
        # Slint workspace crates share the root licensing files.
        if directory.is_relative_to(workspace):
            notices.update(path for path in (workspace / "LICENSES").iterdir() if path.is_file())
        supplement = supplements.get(name, {}) if not notices else {}
        for filename in supplement.get("local_files", []):
            notices.add(directory / filename)
        if supplement.get("standard_text"):
            notices.add(workspace / "LICENSES" / supplement["standard_text"])
        downloads = []
        for entry in supplement.get("files", []):
            url = entry["url"]
            if not re.fullmatch(r"https://raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[0-9a-f]{40}/[\w.-]+", url):
                raise ValueError(f"Invalid pinned notice URL: {url}")
            if url not in download_cache:
                with urllib.request.urlopen(url, timeout=30) as response:
                    download_cache[url] = response.read(1024 * 1024 + 1)
            data = download_cache[url]
            if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError(f"Invalid upstream notice hash for {name}")
            (destination / entry["filename"]).write_bytes(data)
            downloads.append(entry)
        if (not notices and not downloads) or not package.get("license"):
            raise ValueError(f"Missing license metadata/text for {name}; review before packaging")
        copied = []
        for index, path in enumerate(sorted(notices)):
            filename = f"{index:02d}-" + path.name
            shutil.copyfile(path, destination / filename)
            copied.append(filename)
        inventory.append({"name": package["name"], "version": package["version"],
                          "license": package["license"], "repository": package.get("repository"),
                          "source": package.get("source"), "notices": copied,
                          "upstream_notices": downloads, "note": supplement.get("note")})
    lock = workspace / "Cargo.lock"
    shutil.copyfile(lock, output / "Cargo.lock")
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    compiler_notices = sysroot / "share/doc/rust"
    standard = output / "rust-standard-library"
    shutil.copytree(compiler_notices / "licenses", standard / "licenses")
    shutil.copyfile(compiler_notices / "COPYRIGHT-library.html", standard / "COPYRIGHT-library.html")
    (output / "inventory.json").write_text(json.dumps({
        "target": target, "cargo_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "packages": inventory}, indent=2) + "\n", encoding="utf-8")
    print(f"Collected notices for {len(inventory)} locked Rust packages", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    collect(arguments.manifest, arguments.target, arguments.output)
