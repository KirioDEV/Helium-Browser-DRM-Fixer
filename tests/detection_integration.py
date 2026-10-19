"""Exercise real CLI detection against isolated profiles and synthetic PE headers.

No fixture executable/library is executed or loaded. Program Files and profile
environment variables point only inside the temporary tree.
"""

import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cli_integration import snapshot, source


def main():
    executable = Path(sys.argv[1]).resolve()
    helper = Path(sys.argv[2]).resolve()
    passed = 0
    with tempfile.TemporaryDirectory(prefix="helium-detection-ä-中-") as temporary:
        root = Path(temporary).resolve()
        environment = {name.upper(): value for name, value in os.environ.items()}
        for name in ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
                     "ProgramFiles", "ProgramFiles(x86)", "XDG_CONFIG_HOME",
                     "XDG_CACHE_HOME", "TMP", "TEMP", "TMPDIR"):
            directory = root / name.lower()
            directory.mkdir()
            environment[name.upper()] = str(directory)
        # Windows derives ProgramFiles from ProgramW6432 when starting x64
        # children. Keep both inside the fixture, including helper processes.
        environment["PROGRAMW6432"] = environment["PROGRAMFILES"]
        working = root / "working"
        working.mkdir()

        def execute(name, arguments, code=0, *, contains=(), read_only=True,
                    program=executable):
            nonlocal passed
            before = snapshot(root) if read_only else None
            result = subprocess.run([str(program), *map(str, arguments)],
                                    cwd=working, env=environment, capture_output=True,
                                    encoding="utf-8", timeout=20)
            output = result.stdout + result.stderr
            if result.returncode != code or any(text not in output for text in contains):
                raise RuntimeError(f"{name}: expected {code}/{contains}, "
                                   f"got {result.returncode}: {output}")
            if read_only and snapshot(root) != before:
                raise RuntimeError(f"{name}: modified the fixture tree")
            passed += 1
            print(f"{name}: passed", flush=True)
            return output

        execute("conflicting paths", ["--helium-app-path", root,
                "--helium-path", root / "WidevineCdm"], 2)
        execute("restore requires fixed target", ["--helium-app-path", root,
                "--restore"], 2)
        execute("empty application argument", ["--helium-app-path", ""], 2)
        execute("missing application argument", ["--helium-app-path"], 2)
        if sys.platform != "win32":
            execute("Linux retains profile target semantics", ["--helium-app-path",
                    root, "--check"], 2, contains=("only supported on Windows",))
            home_root = root / "var-home"
            real_home = home_root / "test-user"
            real_home.mkdir(parents=True)
            home_link = root / "home-alias"
            home_link.symlink_to(home_root, target_is_directory=True)
            home = home_link / "test-user"
            environment["HOME"] = str(home)
            environment.pop("XDG_CONFIG_HOME")
            environment.pop("XDG_CACHE_HOME")
            profile = real_home / ".config/net.imput.helium"
            profile.mkdir(parents=True)
            (profile / "Local State").write_text("{}", encoding="utf-8")
            target = profile / "WidevineCdm"
            output = execute("symlinked HOME detection", ["--check", "--json"], 3)
            status = json.loads(output)
            if status["state"] != "missing" or status["target"] != str(target):
                raise RuntimeError("HOME was not resolved before profile inspection")
            environment["XDG_CONFIG_HOME"] = str(home / ".config")
            execute("XDG config below symlinked HOME", ["--check"], 3,
                    contains=("Widevine is missing",))
            alias_target = home / ".config/net.imput.helium/WidevineCdm"
            execute("explicit target below symlinked HOME", ["--helium-path",
                    alias_target, "--check"], 3, contains=("Widevine is missing",))
            execute("cache below symlinked HOME", ["--cache-path"], program=helper,
                    contains=(str(real_home / ".cache/helium-drm-fixer"),), read_only=False)
            environment["XDG_CACHE_HOME"] = str(home / ".cache")
            execute("XDG cache below symlinked HOME", ["--cache-path"], program=helper,
                    contains=(str(real_home / ".cache/helium-drm-fixer"),))
            original = source(real_home / "local-source", "1.2.3.4")
            execute("local plan below symlinked HOME", ["--source", "chrome",
                    "--chrome-path", home / "local-source", "--dry-run"],
                    contains=("Local source version: 1.2.3.4",))
            execute("install below symlinked HOME", ["--source", "chrome",
                    "--chrome-path", home / "local-source"], read_only=False,
                    contains=("Installed Widevine 1.2.3.4",))
            execute("installed check below symlinked HOME", ["--check"],
                    contains=("Widevine 1.2.3.4",))
            execute("restore below symlinked HOME", ["--helium-path", alias_target,
                    "--restore"], read_only=False)
            execute("restored missing state", ["--check"], 3,
                    contains=("Widevine is missing",))
            target.symlink_to(original, target_is_directory=True)
            execute("Widevine symlink still rejected", ["--check"], 4,
                    contains=("Symlink rejected",))
            target.unlink()
            moved = profile.with_name("saved-profile")
            profile.rename(moved)
            profile.symlink_to(moved, target_is_directory=True)
            execute("profile symlink still rejected", ["--check"], 4,
                    contains=("Symlink rejected",))
            profile.unlink()
            moved.rename(profile)
            config = real_home / ".config"
            config.rename(real_home / "saved-config")
            config.symlink_to(real_home / "saved-config", target_is_directory=True)
            execute("config symlink still rejected", ["--check"], 4,
                    contains=("Symlink rejected",))
            print(f"{passed} detection CLI scenarios passed")
            return

        original = source(root / "source one", "1.2.3.4")
        replacement = source(root / "source two", "2.0.0.0")
        pe = bytearray((original / "widevinecdm.dll").read_bytes())
        pe[87] = 0  # Synthetic executable header, not a DLL.

        def application(base, versions=("9.0.0.0", "10.0.0.0")):
            for version in versions:
                (base / version).mkdir(parents=True)
            (base / "helium.exe").write_bytes(pe)
            return base

        def inspect(name, base, version="10.0.0.0"):
            execute(name, ["--helium-app-path", base, "--dry-run"],
                    contains=(str(base / version / "WidevineCdm"),))

        def autodetect(name, expected):
            execute(name, ["--dry-run"], contains=(str(expected / "WidevineCdm"),))

        execute("empty isolated environment", ["--check"], 3)
        app = application(root / "Application ä 中")
        (app / "999.invalid").mkdir()
        (app / "4294967296.0.0.0").mkdir()
        (app / "999.0.0.0").write_text("not a directory", encoding="ascii")
        inspect("numeric ordering and invalid entries", app)
        chrome_app = application(root / "chrome-named Helium")
        (chrome_app / "helium.exe").rename(chrome_app / "chrome.exe")
        inspect("chrome-named Helium launcher", chrome_app)
        inspect("chrome-named Helium explicit version", chrome_app / "10.0.0.0", "")
        (chrome_app / "10.0.0.0" / "chrome.exe").write_bytes(b"invalid PE")
        execute("invalid version chrome does not fall back to launcher",
                ["--helium-app-path", chrome_app, "--check"], 4)
        (chrome_app / "10.0.0.0" / "chrome.exe").write_bytes(pe)
        inspect("chrome-named version executable", chrome_app)
        execute("explicit version folder", ["--helium-app-path", app / "9.0.0.0",
                "--dry-run"], contains=(str(app / "9.0.0.0" / "WidevineCdm"),))
        execute("relative application folder", ["--helium-app-path",
                os.path.relpath(app, working), "--dry-run"],
                contains=(str(app / "10.0.0.0" / "WidevineCdm"),))
        execute("missing application directory", ["--helium-app-path",
                root / "absent", "--check"], 3)
        empty = root / "empty application"
        empty.mkdir()
        execute("no numeric version", ["--helium-app-path", empty, "--check"], 3)
        missing = root / "missing exe"
        (missing / "1.0.0.0").mkdir(parents=True)
        execute("missing executable", ["--helium-app-path", missing, "--check"], 3)
        (app / "10.0.0.0" / "helium.exe").write_bytes(b"invalid PE")
        execute("invalid newest executable does not downgrade", ["--helium-app-path",
                app, "--check"], 4)
        (app / "10.0.0.0" / "helium.exe").unlink()
        bad = application(root / "x86 application")
        x86 = bytearray(pe)
        x86[68:70] = b"\x4c\x01"
        (bad / "helium.exe").write_bytes(x86)
        execute("x86 executable rejected", ["--helium-app-path", bad, "--check"],
                4, contains=("not x86_64",))
        ambiguous = application(root / "ambiguous", ("1.0.0.0", "01.0.0.0"))
        execute("numeric aliases rejected", ["--helium-app-path", ambiguous,
                "--check"], 4, contains=("Ambiguous version directories",))
        hardlink = application(root / "hardlink")
        os.link(hardlink / "helium.exe", root / "exe alias")
        execute("hardlinked executable rejected", ["--helium-app-path", hardlink,
                "--check"], 4, contains=("Hard-linked",))

        # A junction needs no symlink privilege and always targets our own fixture.
        junction = root / "junction"
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J",
                                 str(junction), str(app)], capture_output=True)
        if result.returncode:
            raise RuntimeError(f"Cannot create isolated junction: {result.stderr!r}")
        try:
            execute("reparse application path rejected", ["--helium-app-path",
                    junction, "--check"], 4)
        finally:
            junction.rmdir()  # Remove only the junction, never its target.

        # Hold the EXE without sharing: a real native read failure must not cause
        # fallback to another installation. No ACLs or real Program Files change.
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.CreateFileW(str(app / "helium.exe"), 0x80000000, 0,
                                    None, 3, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        before = snapshot(app / "10.0.0.0")
        try:
            execute("unreadable executable rejected", ["--helium-app-path", app,
                    "--check"], 1, read_only=False)
            output = execute("JSON read error is not a repair diagnosis",
                             ["--helium-app-path", app, "--check", "--json"],
                             1, read_only=False)
            value = json.loads(output)
            if value["state"] != "unavailable" or value["exit_code"] != 1:
                raise RuntimeError("Read error was misclassified as a CDM defect")
        finally:
            kernel.CloseHandle(handle)
        if snapshot(app / "10.0.0.0") != before:
            raise RuntimeError("Read failure changed selected version")

        target = app / "10.0.0.0" / "WidevineCdm"
        for name, directory in (("install through app root", original),
                                ("update through app root", replacement)):
            execute(name, ["--helium-app-path", app, "--source", "chrome",
                    "--chrome-path", directory], read_only=False)
        execute("restore exact selected target", ["--helium-path", target,
                "--restore"], read_only=False)
        execute("check restored app target", ["--helium-app-path", app, "--check"],
                contains=("Widevine 1.2.3.4",))
        preserved = snapshot(app / "10.0.0.0")
        (app / "11.0.0.0").mkdir()
        execute("new browser version selected", ["--helium-app-path", app,
                "--check"], 3, contains=("Widevine is missing",))
        execute("old target stays reachable", ["--helium-path", target, "--check"],
                contains=("Widevine 1.2.3.4",))
        if snapshot(app / "10.0.0.0") != preserved:
            raise RuntimeError("Version re-resolution changed the old installation")

        local = Path(environment["LOCALAPPDATA"])
        modern = application(local / "imput" / "Helium" / "Application")
        legacy = application(local / "Helium" / "Application", ("20.0.0.0",))
        system = application(Path(environment["PROGRAMFILES"]) / "Helium" /
                             "Application", ("30.0.0.0",))
        system86 = application(Path(environment["PROGRAMFILES(X86)"]) / "Helium" /
                               "Application", ("40.0.0.0",))
        autodetect("LocalAppData priority", modern / "10.0.0.0")
        (modern / "10.0.0.0" / "helium.exe").write_bytes(b"bad")
        execute("bad local install cannot select system fallback", ["--check"], 4)
        (modern / "10.0.0.0" / "helium.exe").unlink()
        (modern / "10.0.0.0").rmdir()
        (modern / "9.0.0.0").rmdir()
        autodetect("legacy local path", legacy / "20.0.0.0")
        (legacy / "20.0.0.0").rmdir()
        autodetect("ProgramFiles fallback", system / "30.0.0.0")
        (system / "30.0.0.0").rmdir()
        autodetect("ProgramFiles x86 path with x64 executable", system86 / "40.0.0.0")
        environment.pop("LOCALAPPDATA")
        profile = application(Path(environment["USERPROFILE"]) / "AppData" / "Local" /
                              "imput" / "Helium" / "Application", ("50.0.0.0",))
        autodetect("user profile fallback", profile / "50.0.0.0")
        execute("cache uses same profile fallback", ["--cache-path"],
                contains=(str(Path(environment["USERPROFILE"]) / "AppData" /
                              "Local" / "helium-drm-fixer"),), program=helper)
        environment["USERPROFILE"] = "relative-profile"
        execute("relative user profile rejected", ["--check"], 4)
        environment.pop("USERPROFILE")
        autodetect("system fallback without local variables", system86 / "40.0.0.0")
        environment["LOCALAPPDATA"] = "relative-local"
        execute("relative LocalAppData rejected", ["--check"], 4)
        if any(Path(environment["XDG_CACHE_HOME"]).iterdir()):
            raise RuntimeError("Detection unexpectedly created a cache")
    print(f"{passed} detection CLI scenarios passed; synthetic headers never executed")


if __name__ == "__main__":
    main()
