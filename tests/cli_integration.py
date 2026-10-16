"""Run the shipped CLI on synthetic CDMs in an isolated temporary profile.

The small PE/ELF fixtures are header data, never loaded as libraries. Filesystem
snapshots check persistent changes, not write-and-delete syscalls or networking.
An actually running Helium still blocks installation; no test bypass is added.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def source(directory, version):
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(
        json.dumps({"version": version}), encoding="utf-8")
    binary = bytearray(128)
    if sys.platform == "win32":
        binary[:2] = b"MZ"
        binary[0x3c] = 64
        binary[64:68] = b"PE\0\0"
        binary[68:70] = b"\x64\x86"
        binary[87] = 0x20
        binary[88:90] = b"\x0b\x02"
        name = "widevinecdm.dll"
    else:
        binary[:7] = b"\x7fELF\x02\x01\x01"
        binary[16] = 3
        binary[18] = 62
        name = "libwidevinecdm.so"
    (directory / name).write_bytes(binary)
    (directory / "LICENSE").write_text("Synthetic CLI fixture", encoding="ascii")
    return directory


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, digest)
    return result


def main():
    executable, helper = (Path(arg).resolve() for arg in sys.argv[1:])
    passed = 0
    with tempfile.TemporaryDirectory(prefix="helium-cli-ä-中-") as temporary:
        root = Path(temporary).resolve()
        environment = os.environ.copy()
        for variable in ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
                         "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMP", "TEMP", "TMPDIR"):
            directory = root / variable.lower()
            directory.mkdir()
            environment[variable] = str(directory)
        working = root / "working directory"
        working.mkdir()

        def execute(name, arguments, code=0, *, contains=(), read_only=False,
                    program=executable):
            nonlocal passed
            before = snapshot(root) if read_only else None
            result = subprocess.run([str(program), *map(str, arguments)],
                                    cwd=working, env=environment, capture_output=True,
                                    encoding="utf-8", timeout=20)
            output = result.stdout + result.stderr
            if result.returncode != code:
                raise RuntimeError(f"{name}: expected {code}, got {result.returncode}: {output}")
            for text in contains:
                if text not in output:
                    raise RuntimeError(f"{name}: missing {text!r}: {output}")
            if code and "Installed Widevine" in output:
                raise RuntimeError(f"{name}: error reported installation success")
            if read_only and snapshot(root) != before:
                raise RuntimeError(f"{name}: changed the isolated filesystem")
            passed += 1
            print(f"{name}: passed", flush=True)
            return output

        profile = root / "Helium profile ä 中"
        profile.mkdir()
        target = profile / "WidevineCdm"
        location = ["--helium-path", target]
        first = source(root / "Chrome source 1 ä 中", "1.2.3.4")
        second = source(root / "Chrome source 2 ä 中", "2.0.0.0")
        original_sources = (snapshot(first), snapshot(second))

        def local(directory, extra=(), destination=location):
            return [*destination, "--source", "chrome", "--chrome-path", directory, *extra]

        execute("help", ["--help"], contains=("Usage:",), read_only=True)
        execute("version", ["--version"], read_only=True)
        execute("missing installation", [*location, "--check"], 3,
                contains=("Widevine is missing",), read_only=True)
        execute("offline Google plan", [*location, "--dry-run"],
                contains=("Online version unknown",), read_only=True)
        execute("local source plan", local(first, ["--dry-run"]),
                contains=("1.2.3.4", "not publisher-verified"), read_only=True)

        output = execute("first install", local(first), contains=(
            "publisher integrity is not verified", "Installed Widevine 1.2.3.4"))
        steps = ("Checking installation source", "Preparing Widevine",
                 "Prepared files checked", "Installing prepared files",
                 "Checking installed files", "Installed Widevine")
        if [output.index(step) for step in steps] != sorted(output.index(step) for step in steps):
            raise RuntimeError("Installation phases were reported out of order")
        first_installed = snapshot(target)
        execute("check installed source", [*location, "--check"],
                contains=("Widevine 1.2.3.4", "not established"), read_only=True)
        execute("update", local(second), contains=("Installed Widevine 2.0.0.0",))
        execute("check updated source", [*location, "--check"],
                contains=("Widevine 2.0.0.0",), read_only=True)
        execute("restore previous installation", [*location, "--restore"],
                contains=("Recovery/restore completed",))
        if snapshot(target) != first_installed:
            raise RuntimeError("Restore did not preserve the original files and timestamps")
        execute("idempotent restore", [*location, "--restore"])
        execute("invalid repeated option", [*location, "--check", "--check"], 2,
                read_only=True)
        execute("conflicting modes", [*location, "--check", "--restore"], 2,
                read_only=True)

        invalid = source(root / "invalid local source", "3.0.0.0")
        (invalid / "manifest.json").write_text('{"version":"../bad"}', encoding="ascii")
        execute("invalid source preserves installation", local(invalid), 4, read_only=True)
        nested = source(target / "nested source", "3.0.0.0")
        execute("source inside target rejected", local(nested), 4,
                contains=("Source must be outside the target",), read_only=True)
        shutil.rmtree(nested)
        package = root / "invalid package.crx3"
        package.write_bytes(b"Cr24\x03\0\0\0" + b"\0" * 120)
        execute("invalid package has no fallback", [*location, "--source", "package",
                "--package", package], 4, read_only=True)

        invalid_profile = root / "invalid profile"
        invalid_profile.mkdir()
        invalid_target = source(invalid_profile / "WidevineCdm", "1.2.3.4")
        (invalid_target / "manifest.json").write_text("invalid JSON", encoding="ascii")
        execute("locally invalid installation", ["--helium-path",
                invalid_profile / "WidevineCdm", "--check"], 4, read_only=True)

        empty_profile = root / "first install restore"
        empty_profile.mkdir()
        empty_target = empty_profile / "WidevineCdm"
        empty_location = ["--helium-path", empty_target]
        execute("install with no previous CDM", local(second, destination=empty_location))
        execute("restore to missing CDM", [*empty_location, "--restore"])
        execute("check restored missing CDM", [*empty_location, "--check"], 3, read_only=True)

        crash_profile = root / "interrupted installation"
        crash_profile.mkdir()
        crash_target = crash_profile / "WidevineCdm"
        crash_location = ["--helium-path", crash_target]
        execute("crash between rename and journal", ["--crash", crash_target, "new_renamed"],
                77, program=helper)
        execute("check pending recovery", [*crash_location, "--check"], 5,
                contains=("Pending recovery",), read_only=True)
        execute("plan pending recovery", [*crash_location, "--dry-run"],
                contains=("Blocked by pending transaction",), read_only=True)
        execute("pending recovery blocks install", local(second, destination=crash_location),
                5, read_only=True)
        execute("recover using production CLI", [*crash_location, "--restore"])
        execute("check recovered installation", [*crash_location, "--check"],
                contains=("Widevine 1.2.3.4",), read_only=True)
        if (snapshot(first), snapshot(second)) != original_sources:
            raise RuntimeError("CLI changed the source files")
        for name in ("xdg_cache_home", "localappdata"):
            if any((root / name).iterdir()):
                raise RuntimeError("Local CLI workflow unexpectedly created a cache")
    print(f"{passed} production CLI scenarios passed; synthetic CDMs were never loaded")


if __name__ == "__main__":
    main()
