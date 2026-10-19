"""Wrap a finished standalone GUI payload in a bounded unsigned update package."""

from pathlib import Path
import shutil
import tempfile

from package_app_release import SHARE, app_executable, build_release, read_regular

ROOT = Path(__file__).resolve().parent.parent


def gui_candidate(build, executable, version, platform, output):
    output.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="gui-update-", dir=output.parent) as temporary:
        staging = Path(temporary)
        binary = staging / app_executable(platform, True)
        binary.parent.mkdir()
        binary.write_bytes(read_regular(executable))
        for name in ("README.md", "LICENSE", "SECURITY.md", "THIRD_PARTY.md"):
            destination = staging / SHARE / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        for dependency, filename, notice in (("json", "LICENSE.MIT", "nlohmann-json-MIT.txt"),
                                             ("miniz", "LICENSE", "miniz-MIT.txt")):
            destination = staging / SHARE / "licenses" / notice
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(build / f"_deps/{dependency}-src/{filename}", destination)
        return build_release(staging, version, platform, output, gui=True)
