"""Open the real GUI, read an isolated missing-CDM status, and close it."""

import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile

from cli_integration import snapshot, source


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="helium-gui-") as temporary:
        root = Path(temporary)
        environment = {key.upper(): value for key, value in os.environ.items()}
        for name in ("LOCALAPPDATA", "USERPROFILE", "HOME", "XDG_CONFIG_HOME",
                     "XDG_CACHE_HOME", "APPDATA", "ProgramFiles", "ProgramFiles(x86)"):
            directory = root / name.lower()
            directory.mkdir()
            environment[name.upper()] = str(directory)
        environment["PROGRAMW6432"] = environment["PROGRAMFILES"]
        if sys.platform == "win32":
            if sys.argv[2:] == ["--packaged"]:
                sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
                from windows_gui_resources import verify_notices
                verify_notices(executable)
            from windows_portable import check_notices, imports
            dependencies = imports(executable)
            if "msvcrt.dll" in dependencies:
                raise RuntimeError("GUI must use UCRT consistently, not legacy MSVCRT")
            forbidden = {name for name in dependencies if
                         name.startswith(("slint", "qt", "libstdc++", "libgcc", "libwinpthread", "vcruntime", "msvcp"))}
            if forbidden:
                raise RuntimeError(f"GUI requires adjacent runtime DLLs: {forbidden}")
            check_notices(executable)
            isolated = root / executable.name
            shutil.copyfile(executable, isolated)
            executable = isolated
            environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
            # Windows PowerShell/UI Automation initializes these empty host
            # directories. Prepare them before measuring application changes.
            (Path(environment["LOCALAPPDATA"]) / "Microsoft/Windows/Caches").mkdir(parents=True)
            (Path(environment["USERPROFILE"]) / "AppData/Roaming").mkdir(parents=True)
            app = Path(environment["LOCALAPPDATA"]) / "imput/Helium/Application"
            (app / "1.0.0.0").mkdir(parents=True)
            fixture = source(root / "synthetic", "1.2.3.4")
            pe = bytearray((fixture / "widevinecdm.dll").read_bytes())
            pe[87] = 0
            (app / "chrome.exe").write_bytes(pe)
        else:
            profile = Path(environment["XDG_CONFIG_HOME"]) / "net.imput.helium"
            profile.mkdir()
            (profile / "Local State").write_text("{}", encoding="utf-8")
            # The GUI's system font backend creates its own font cache. Warm it
            # in this isolated profile before checking for application writes.
            subprocess.run([sys.executable, "-c",
                            "import ctypes; fontconfig=ctypes.CDLL('libfontconfig.so.1'); "
                            "assert fontconfig.FcInit() != 0"],
                           env=environment, cwd=root, check=True, timeout=15)
        before = snapshot(root)
        image_arguments = ["--appimage-extract-and-run"] if sys.argv[2:] == ["--appimage"] else []
        result = subprocess.run([str(executable), *image_arguments, "--smoke-test"], env=environment,
                                cwd=root, capture_output=True, timeout=35)
        if result.returncode:
            raise RuntimeError(f"GUI failed: {result.returncode}: {result.stderr!r}")
        if sys.platform == "win32":
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            script = Path(__file__).with_name("gui_interaction.ps1").resolve()
            result = subprocess.run([str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass",
                                     "-File", str(script), "-Application", str(executable)],
                                    env=environment, cwd=root, capture_output=True, timeout=40)
            if result.returncode:
                raise RuntimeError(f"GUI interaction failed: {result.stdout!r}: {result.stderr!r}")
        if snapshot(root) != before:
            after = snapshot(root)
            raise RuntimeError(f"GUI inspection changed the isolated fixture: "
                               f"added={set(after) - set(before)}, removed={set(before) - set(after)}, "
                               f"changed={[name for name in before if name in after and before[name] != after[name]]}")
    print("GUI startup, asynchronous local inspection and clean exit passed")


if __name__ == "__main__":
    main()
