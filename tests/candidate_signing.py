"""Exercise candidate signing with temporary keys and inert binary fixtures."""

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from sign_app_candidate import inspect_candidate, sign_candidate


def exercise_candidate_signing(helper, program, root, package, public, key, other_key, openssl):
    passed = 0
    manifest = package.with_name(package.name + ".manifest.json")
    original_package, original_manifest = package.read_bytes(), manifest.read_bytes()
    tool = Path(__file__).resolve().parents[1] / "tools" / "sign_app_candidate.py"

    def success(name, condition):
        nonlocal passed
        if not condition:
            raise RuntimeError(name)
        passed += 1
        print(name + ": passed", flush=True)

    def rejected(name, action):
        try:
            action()
        except (ValueError, OSError):
            success(name, True)
        else:
            raise RuntimeError("Unsafe candidate accepted: " + name)

    # Inspection never treats the unsigned manifest's digest as publisher trust.
    value, raw_manifest, raw_package = inspect_candidate(package)
    success("candidate inspection preserves exact bytes",
            raw_manifest == original_manifest and raw_package == original_package)
    inspected = subprocess.run([sys.executable, str(tool), "--candidate", str(package), "--check-only"],
                               capture_output=True, timeout=20)
    success("candidate CLI reports unsigned status",
            inspected.returncode == 0 and json.loads(inspected.stdout)["signature_verified"] is False)
    packaged_output = root / "packaging CLI Unicode output"
    packaged_output.mkdir()
    packed = subprocess.run([sys.executable, str(tool.with_name("package_app_release.py")),
                             "--staging", str(root / "staging"), "--version", value["version"],
                             "--platform", value["platform"], "--output", str(packaged_output)],
                            capture_output=True, timeout=25)
    if packed.returncode:
        raise RuntimeError(f"Release packaging CLI failed: {packed.stderr!r}")
    success("release packaging CLI handles Unicode output paths",
            (packaged_output / package.name).read_bytes() == original_package)
    signed_dir = root / "signed candidate exact bytes"
    paths = sign_candidate(package, public, key, signed_dir, openssl)
    success("candidate signing preserves ZIP and manifest bytes",
            paths[0].read_bytes() == original_package and paths[1].read_bytes() == original_manifest and
            paths[2].read_bytes() == package.with_name(package.name + ".manifest.sig").read_bytes())
    cli_output = root / "candidate signer CLI output"
    signed = subprocess.run([sys.executable, str(tool), "--candidate", str(package), "--public-key", str(public),
                             "--signing-key", str(key), "--output", str(cli_output), "--openssl", openssl],
                            capture_output=True, timeout=25)
    if signed.returncode:
        raise RuntimeError(f"Candidate signing CLI failed: {signed.stderr!r}")
    success("candidate signing CLI uses pinned trust and exact bytes",
            signed.returncode == 0 and (cli_output / package.name).read_bytes() == original_package and
            (cli_output / (package.name + ".manifest.sig")).read_bytes() == paths[2].read_bytes())
    checked = subprocess.run([str(helper), "--inspect-app-release", str(paths[0]), str(public)],
                             capture_output=True, timeout=20)
    success("native offline release inspection accepts signed candidate",
            checked.returncode == 0 and json.loads(checked.stdout)["package_verified"] is True and
            json.loads(checked.stdout)["installation_performed"] is False)
    if program:
        rejected_cli = subprocess.run([str(program), "--verify-app-release", str(paths[0]), "--json"],
                                      capture_output=True, timeout=20)
        success("shipped release inspector rejects unrelated signer",
                rejected_cli.returncode == 4 and b'"package_verified":true' not in rejected_cli.stdout)
    before = {path.name: path.read_bytes() for path in signed_dir.iterdir()}
    rejected("candidate signer refuses existing output", lambda: sign_candidate(package, public, key, signed_dir, openssl))
    success("existing signed release remains unchanged",
            before == {path.name: path.read_bytes() for path in signed_dir.iterdir()})
    wrong = root / "wrong signer output"
    rejected("candidate signer rejects key not matching project pin",
             lambda: sign_candidate(package, public, other_key, wrong, openssl))
    success("wrong signing key creates no output", not wrong.exists())
    alias = root / "candidate alias"
    os.link(package, alias)
    rejected("candidate inspection rejects hardlinked ZIP", lambda: inspect_candidate(package))
    alias.unlink()
    for fault in ("zip hash", "manifest duplicate key", "manifest size type", "extra schema field",
                  "wrong repository", "runtime path", "missing license", "bad executable flag",
                  "ZIP inventory", "ZIP contents", "ZIP permissions"):
        candidate = json.loads(original_manifest)
        changed_package = original_package
        if fault == "zip hash":
            changed_package = original_package[:-1] + bytes([original_package[-1] ^ 1])
        elif fault == "manifest size type": candidate["package"]["size"] = True
        elif fault == "extra schema field": candidate["public_key"] = "not a trust root"
        elif fault == "wrong repository": candidate["repository"] = "other/repo"
        elif fault == "runtime path": candidate["files"][0]["path"] = "bin/untrusted.dll"
        elif fault == "missing license": candidate["files"] = candidate["files"][:-1]
        elif fault == "bad executable flag": candidate["files"][0]["executable"] = False
        elif fault.startswith("ZIP "):
            with zipfile.ZipFile(io.BytesIO(original_package)) as archive:
                entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
            result = io.BytesIO()
            with zipfile.ZipFile(result, "w") as archive:
                for index, (entry, content) in enumerate(entries):
                    if index == 0:
                        if fault == "ZIP inventory": entry.filename = "../escape"
                        if fault == "ZIP contents": content += b"tampered"
                        if fault == "ZIP permissions": entry.external_attr = 0o120755 << 16
                    archive.writestr(entry, content)
            changed_package = result.getvalue()
            candidate["package"]["size"] = len(changed_package)
            candidate["package"]["sha256"] = hashlib.sha256(changed_package).hexdigest()
        changed_manifest = json.dumps(candidate, separators=(",", ":")).encode()
        if fault == "manifest duplicate key":
            changed_manifest = b'{"version":"1.2.3",' + changed_manifest[1:]
        package.write_bytes(changed_package)
        manifest.write_bytes(changed_manifest)
        try:
            rejected("candidate rejects " + fault, lambda: inspect_candidate(package))
        finally:
            package.write_bytes(original_package)
            manifest.write_bytes(original_manifest)
    # Signed inspection must bind all three exact files, too.
    paths[0].write_bytes(original_package[:-1])
    checked = subprocess.run([str(helper), "--inspect-app-release", str(paths[0]), str(public)],
                             capture_output=True, timeout=20)
    success("native release inspection rejects truncated signed ZIP", checked.returncode != 0)
    paths[0].write_bytes(original_package)
    success("source candidate remains unchanged after signing/rejections",
            package.read_bytes() == original_package and manifest.read_bytes() == original_manifest)
    older = root / "older inspection candidate"
    older.mkdir()
    previous = json.loads(original_manifest)
    previous["version"] = "0.0.1"
    previous["package"]["name"] = f"helium-drm-fixer-cpp-0.0.1-{previous['platform']}.zip"
    old_package = older / previous["package"]["name"]
    old_package.write_bytes(original_package)
    old_package.with_name(old_package.name + ".manifest.json").write_text(json.dumps(previous), encoding="utf-8")
    old_signed = sign_candidate(old_package, public, key, root / "older signed inspection candidate", openssl)
    checked = subprocess.run([str(helper), "--inspect-app-release", str(old_signed[0]), str(public)],
                             capture_output=True, timeout=20)
    success("offline release inspection permits older versions without installing",
            checked.returncode == 0 and json.loads(checked.stdout)["version"] == "0.0.1" and
            json.loads(checked.stdout)["installation_performed"] is False)
    return passed
