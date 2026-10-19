"""Test GUI identity, signatures, parent-exit handoff, restart and rollback."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from package_app_release import SHARE, REPOSITORY, build_release, app_executable, sign_manifest
from sign_app_candidate import inspect_candidate
import ci_release_signing as signing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--appimage", type=Path, help="Optional real AppImage containing the test helper")
    args = parser.parse_args()
    helper = args.helper.resolve()
    windows = sys.platform == "win32"
    platform = "windows-x64" if windows else "linux-x86_64-ubuntu24.04"
    with tempfile.TemporaryDirectory(prefix="gui-up-") as temporary:
        root = Path(temporary)
        env = os.environ.copy()
        env["FIXER_TEST_APP_TRUST"] = str(root / "public.der")
        env["FIXER_TEST_GUI_RESTART"] = str(root / "restart.txt")

        def execute(arguments, accepted=True, **kwargs):
            result = subprocess.run(list(map(str, arguments)), env=env, capture_output=True,
                                    timeout=30, **kwargs)
            if (result.returncode == 0) != accepted:
                raise RuntimeError(f"Unexpected result {result.returncode}: {result.stderr!r}")
            return result

        execute([args.openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                 "-out", root / "signer.pem"])
        execute([args.openssl, "pkey", "-in", root / "signer.pem", "-pubout", "-outform", "DER",
                 "-out", root / "public.der"])
        name = Path(app_executable(platform, True)).name
        native = root / "native/usr/bin" / ("fixture.exe" if windows else "fixture")
        native.parent.mkdir(parents=True)
        (root / "native/usr/lib").mkdir()
        original = helper.read_bytes()
        native.write_bytes(original)
        native.chmod(0o755)
        old = bytearray(args.appimage.read_bytes() if args.appimage else original)
        if not windows:
            old[8:11] = b"AI\x02"
        new = bytes(old) + b"GUI signed update fixture"
        destination = root / "app"
        destination.mkdir()
        target = destination / name
        target.write_bytes(old)
        target.chmod(0o755)
        running = target if windows or args.appimage else native
        if not windows:
            # Simulate a distro whose configured HOME traverses a system link.
            home_alias = root / "home-alias"
            home_alias.symlink_to(root, target_is_directory=True)
            env["HOME"] = str(home_alias)
            env["APPIMAGE"] = str(home_alias / "app" / name)
        staging = root / "staging"
        staging.mkdir()
        binary = staging / app_executable(platform, True)
        binary.parent.mkdir()
        binary.write_bytes(new)
        for document in ("README.md", "LICENSE", "SECURITY.md", "THIRD_PARTY.md",
                         "licenses/nlohmann-json-MIT.txt", "licenses/miniz-MIT.txt"):
            path = staging / SHARE / document
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic GUI update fixture\n", encoding="utf-8")
        output = root / "packages"
        output.mkdir()
        package, manifest, signature = build_release(
            staging, "1.2.3", platform, output, root / "signer.pem", args.openssl, gui=True)
        inspect_candidate(package)
        execute([helper, "--inspect", package])
        print("Signed GUI package accepted", flush=True)
        saved = signature.read_bytes()
        signature.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])
        execute([helper, "--inspect", package], accepted=False)
        signature.write_bytes(saved)
        original_manifest = manifest.read_bytes()
        wrong_role = json.loads(original_manifest)
        wrong_role["app_id"] = "helium-drm-fixer-cpp"
        role_bytes = json.dumps(wrong_role).encode("utf-8")
        manifest.write_bytes(role_bytes)
        signature.write_bytes(sign_manifest(role_bytes, root / "signer.pem", args.openssl))
        execute([helper, "--inspect", package], accepted=False)
        manifest.write_bytes(original_manifest)
        signature.write_bytes(saved)
        print("Valid signature with wrong application identity rejected", flush=True)
        saved_zip = package.read_bytes()
        package.write_bytes(saved_zip[:-1] + bytes([saved_zip[-1] ^ 1]))
        execute([helper, "--inspect", package], accepted=False)
        package.write_bytes(saved_zip)
        print("Tampered signature and package rejected", flush=True)

        # Even a correctly signed CLI package must not replace the GUI.
        cli_binary = staging / app_executable(platform)
        cli_binary.write_bytes(new)
        binary.unlink()
        cli_output = root / "cli"
        cli_output.mkdir()
        cli_package = build_release(staging, "1.2.3", platform, cli_output,
                                    root / "signer.pem", args.openssl)[0]
        execute([helper, "--inspect", cli_package], accepted=False)
        print("CLI-to-GUI package substitution rejected", flush=True)

        prefix = f"https://github.com/{REPOSITORY}/releases/download/v1.2.3/"
        release = {"draft": False, "prerelease": False, "tag_name": "v1.2.3",
                   "html_url": f"https://github.com/{REPOSITORY}/releases/tag/v1.2.3",
                   "assets": [{"name": p.name, "state": "uploaded", "size": p.stat().st_size,
                               "browser_download_url": prefix + p.name}
                              for p in (package, manifest, signature)]}
        metadata = root / "release.json"

        def metadata_state(value, expected=None, accepted=True):
            metadata.write_text(json.dumps(value), encoding="utf-8")
            result = execute([helper, "--metadata", metadata], accepted=accepted)
            if accepted and json.loads(result.stdout)["state"] != expected:
                raise RuntimeError(f"Unexpected update state: {result.stdout!r}")

        metadata_state(release, "update_available")
        missing = copy.deepcopy(release)
        missing["assets"].pop()
        metadata_state(missing, "no_compatible_package")
        preview = copy.deepcopy(release)
        preview["prerelease"] = True
        metadata_state(preview, accepted=False)
        duplicate = copy.deepcopy(release)
        duplicate["assets"].append(duplicate["assets"][-1])
        metadata_state(duplicate, accepted=False)
        print("Unsigned/incomplete previews and duplicate assets rejected", flush=True)

        sha = "a" * 40
        repository = {"full_name": REPOSITORY}
        run = {"id": 123, "status": "in_progress", "conclusion": None, "event": "push",
               "head_branch": "main", "head_sha": sha, "path": ".github/workflows/gui-preview.yml",
               "repository": repository, "head_repository": repository}
        signing.validate_run(run, "123", REPOSITORY, sha, "123", gui=True)
        try:
            signing.validate_run(run, "123", REPOSITORY, sha, "123")
        except ValueError:
            pass
        else:
            raise RuntimeError("CLI signer accepted a GUI build run")
        jobs = {"total_count": 2, "jobs": [{"name": n, "status": "completed", "conclusion": "success"}
                                          for n in ("windows-gui", "linux-gui")]}
        signing.validate_build_jobs(jobs, gui=True)
        jobs["jobs"][1]["conclusion"] = "failure"
        try:
            signing.validate_build_jobs(jobs, gui=True)
        except ValueError:
            pass
        else:
            raise RuntimeError("GUI signing allowed a failed build")
        print("GUI signing provenance and completed-job gates passed", flush=True)

        if not windows and not args.appimage:
            outside = root / "outside-bundle.so"
            outside.write_bytes(b"must not be copied into the helper")
            alias = root / "native/usr/lib/outside.so"
            alias.symlink_to(outside)
            invalid = root / "invalid-library-config.json"
            invalid.write_text(json.dumps({"target": str(target), "package": str(package)}))
            try:
                rejected = execute([native, invalid], accepted=False)
                if b"outside its bundle" not in rejected.stderr:
                    raise RuntimeError(f"Wrong helper library rejection: {rejected.stderr!r}")
                if target.read_bytes() != bytes(old):
                    raise RuntimeError("Unsafe helper library changed the GUI")
            finally:
                alias.unlink()
            print("Helper library link escaping the bundle rejected", flush=True)

        def transaction(restore=False, tamper=False, recovery=False):
            config = root / "config.json"
            config.write_text(json.dumps({"target": str(target), "package": str(package),
                                          "restore": restore, "hold": True}), encoding="utf-8")
            before = target.read_bytes() if target.exists() else None
            launcher = native if recovery else running
            arguments = [str(launcher)] + (["--appimage-extract-and-run"] if args.appimage and not recovery else []) + [str(config)]
            process = subprocess.Popen(arguments, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError(f"GUI handoff failed: {process.stderr.read()!r}")
                job = Path(json.loads(line)["job"])
                time.sleep(0.15)
                observed = target.read_bytes() if target.exists() else None
                if process.poll() is not None or observed != before:
                    raise RuntimeError("App replaced before its parent exited")
                if tamper:
                    request = json.loads((job / "request.json").read_text())
                    payload = Path(request["directory"]) / app_executable(platform, True)
                    payload.write_bytes(b"changed after helper verification")
                process.communicate(b"exit\n", timeout=10)
                deadline = time.monotonic() + 15
                marker = root / "restart.txt"
                while not marker.exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"GUI restart missing: {(job / 'status.json').read_text()}")
                    time.sleep(0.05)
                marker.unlink()
                state = json.loads((job / "status.json").read_text())["state"]
                if state != ("failed" if tamper else "restored" if restore else "installed"):
                    raise RuntimeError(f"Wrong GUI helper state: {state}")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

        transaction(tamper=True)
        if target.read_bytes() != bytes(old):
            raise RuntimeError("Tampered handoff changed the original GUI")
        print("Tampered handoff rejected; original GUI preserved and restarted", flush=True)
        transaction()
        if target.read_bytes() != new:
            raise RuntimeError("GUI update bytes differ")
        print("Parent exit, verified replacement and GUI restart passed", flush=True)
        target.rename(root / "preserved-new-version")
        transaction(restore=True, recovery=True)
        if target.read_bytes() != bytes(old):
            raise RuntimeError("GUI rollback bytes differ")
        if (root / "preserved-new-version").read_bytes() != new:
            raise RuntimeError("Recovery changed the preserved new-version bytes")
        print("Missing target recovered from backup and restarted", flush=True)


if __name__ == "__main__":
    main()
