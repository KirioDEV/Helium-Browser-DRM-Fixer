"""Sign existing successful main CI candidates; never publish or execute them."""

import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from package_app_release import REPOSITORY, read_regular
from sign_app_candidate import inspect_candidate, require, sign_candidate


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = {
    "windows-x64": "windows-x64-unsigned-update-candidate",
    "linux-x86_64-ubuntu24.04": "linux-x86_64-unsigned-update-candidate",
}
INPUT = ROOT / "build" / "signing-input"
OUTPUT = ROOT / "build" / "signed-release"


def validate_run(run, run_id, repository, sha):
    require(repository == REPOSITORY, "Signing is restricted to the release repository")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "Invalid build run ID")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid source commit")
    require(type(run.get("id")) is int and str(run["id"]) == run_id and
            run.get("status") == "completed" and run.get("conclusion") == "success" and
            run.get("event") == "push" and run.get("head_branch") == "main" and
            run.get("head_sha") == sha and
            run.get("path") == ".github/workflows/build.yml" and
            run.get("repository", {}).get("full_name") == repository and
            run.get("head_repository", {}).get("full_name") == repository,
            "Expected a successful main push build from this exact repository and commit")


def candidates(directory, version):
    result = []
    require({entry.name for entry in directory.iterdir()} == set(ARTIFACTS),
            "Expected exactly both platform directories")
    for platform in ARTIFACTS:
        folder = directory / platform
        require(folder.is_dir() and not folder.is_symlink(), "Invalid platform directory")
        name = f"helium-drm-fixer-cpp-{version}-{platform}.zip"
        require({entry.name for entry in folder.iterdir()} == {name, name + ".manifest.json"},
                "Unexpected candidate files/version")
        candidate = folder / name
        value, _, _ = inspect_candidate(candidate)
        require(value["version"] == version and value["platform"] == platform,
                "Candidate platform/version mismatch")
        result.append((platform, candidate))
    return result


def project_version():
    text = read_regular(ROOT / "CMakeLists.txt", 65536).decode("utf-8")
    match = re.search(r"project\(helium_drm_fixer VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES", text)
    require(match is not None, "Cannot determine project version")
    return match[1]


def download():
    run_id = os.environ["BUILD_RUN_ID"]
    repository, sha = os.environ["GITHUB_REPOSITORY"], os.environ["BUILD_SOURCE_SHA"]
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "Invalid build run ID")
    require(repository == REPOSITORY, "Unexpected repository")
    require(os.environ.get("GITHUB_REF") == "refs/heads/main", "Select main to sign releases")
    response = subprocess.run(["gh", "api", f"repos/{repository}/actions/runs/{run_id}"],
                              check=True, capture_output=True, timeout=60)
    validate_run(json.loads(response.stdout), run_id, repository, sha)
    INPUT.parent.mkdir(exist_ok=True)
    INPUT.mkdir(mode=0o700)
    for platform, artifact in ARTIFACTS.items():
        subprocess.run(["gh", "run", "download", run_id, "--repo", repository,
                        "--name", artifact, "--dir", str(INPUT / platform)],
                       check=True, timeout=180)
    candidates(INPUT, project_version())
    print(f"Checked both candidates from successful build {run_id} at {sha}")


def sign(openssl_path="openssl"):
    # Validate both complete inventories before materializing the private key.
    version = project_version()
    selected = candidates(INPUT, version)
    require(not OUTPUT.exists(), "Signed output directory already exists")
    pem = os.environ.pop("RELEASE_SIGNING_KEY_PEM", "")
    require(bool(os.environ.get("RELEASE_SIGNING_KEY_PASSPHRASE")), "Missing passphrase secret")
    require(pem.strip().startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----") and
            pem.strip().endswith("-----END ENCRYPTED PRIVATE KEY-----") and len(pem) <= 32768,
            "Missing or invalid encrypted PEM secret")
    try:
        # The temporary key is outside the workspace and artifact upload tree.
        with tempfile.TemporaryDirectory(prefix="helium-release-key-") as temporary:
            key = Path(temporary) / "release.pem"
            descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
                stream.write(pem.strip() + "\n")
            del pem
            OUTPUT.mkdir(mode=0o700)
            for platform, candidate in selected:
                sign_candidate(candidate, ROOT / "keys" / "app-update-public.der", key,
                               OUTPUT / platform, openssl_path=openssl_path,
                               password_env="RELEASE_SIGNING_KEY_PASSPHRASE")
    finally:
        os.environ.pop("RELEASE_SIGNING_KEY_PASSPHRASE", None)
    # Export only the checked Windows program, without executing the payload.
    # Its manifest hash is already covered by the verified release signature.
    windows_package = next((OUTPUT / "windows-x64").glob("*.zip"))
    _, _, package_bytes = inspect_candidate(windows_package)
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
        executable_bytes = archive.read("bin/helium_drm_fixer.exe")
    with (OUTPUT / "windows-x64" / "helium_drm_fixer.exe").open("xb") as stream:
        stream.write(executable_bytes)
    base = f"https://github.com/{REPOSITORY}/releases/download/v{version}"
    notes = [f"# Helium DRM Fixer {version}", "",
             f"**[Windows 11 x64 herunterladen (.exe)]({base}/helium_drm_fixer.exe)**", "",
             "Standalone-Konsolenprogramm mit eingebundenen Laufzeitbibliotheken und Lizenzhinweisen.",
             "", "<details>", "<summary>Linux, Update-Pakete und Signaturen</summary>", ""]
    for platform in ARTIFACTS:
        name = f"helium-drm-fixer-cpp-{version}-{platform}.zip"
        for suffix in ("", ".manifest.json", ".manifest.sig"):
            notes.append(f"- [{name}{suffix}]({base}/{name}{suffix})")
    notes.extend(["", "</details>", ""])
    (OUTPUT / "release-notes.md").write_text("\n".join(notes), encoding="utf-8")
    print("Both candidates signed and verified; standalone Windows EXE exported. Nothing published.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("download", "sign"))
    args = parser.parse_args()
    try:
        {"download": download, "sign": sign}[args.operation]()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        # Do not render exception details originating from secrets or subprocesses.
        parser.exit(1, "Release signing failed; check build identity, candidate files and signing secrets.\n")


if __name__ == "__main__":
    main()
