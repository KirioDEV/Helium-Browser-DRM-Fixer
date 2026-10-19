"""Exercise the GUI update backend inside a real AppImage, using test-only trust."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build, preview = args.build.resolve(), args.preview.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    appdir = output / "AppDir"
    # This test fixture needs runtime libraries, not the production notice tree.
    def ignore(directory, names):
        return ["helium-drm-fixer"] if Path(directory).name == "share" else []
    shutil.copytree(preview / "work/AppDir", appdir, symlinks=True, ignore=ignore)
    helper = build / "fixer_gui_update_tests"
    shutil.copyfile(helper, appdir / "usr/bin/helium_drm_fixer_gui")
    (appdir / "usr/bin/helium_drm_fixer_gui").chmod(0o755)
    image = output / "fixture.AppImage"
    tools = preview / "work/tools"
    environment = {**os.environ, "ARCH": "x86_64", "VERSION": "test-only",
                   "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}
    subprocess.run([str(tools / "appimagetool-extracted/squashfs-root/AppRun"),
                    "--runtime-file", str(tools / "runtime"), str(appdir), str(image)],
                   env=environment, check=True, stdout=subprocess.DEVNULL)
    image.chmod(0o755)
    tests = Path(__file__).resolve().parent.parent / "tests/gui_updates.py"
    subprocess.run([sys.executable, str(tests), "--helper", str(helper),
                    "--appimage", str(image), "--openssl", "openssl"], check=True)


if __name__ == "__main__":
    main()
