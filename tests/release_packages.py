"""Cross-check release packaging/signatures with the native Windows/Linux verifier."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from package_app_release import DOMAIN, SHARE, build_release, sign_manifest
from cli_integration import source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    helper = args.helper.resolve()
    passed = 0
    with tempfile.TemporaryDirectory(prefix="helium-release-ä-中-") as temporary:
        root = Path(temporary)
        key, public = root / "signer.pem", root / "public.der"

        def command(arguments, data=None):
            return subprocess.run(arguments, input=data, capture_output=True,
                                  timeout=90, check=True, cwd=root).stdout

        def generate(bits, private, public_file):
            command([args.openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                     f"rsa_keygen_bits:{bits}", "-out", private.name])
            public_file.write_bytes(command([args.openssl, "pkey", "-in", private.name,
                                             "-pubout", "-outform", "DER"]))

        generate(3072, key, public)
        other_key, other_public = root / "other.pem", root / "other.der"
        generate(3072, other_key, other_public)
        staging = root / "staging"
        staging.mkdir()
        seed = source(root / "binary source", "1.2.3.4")
        windows = sys.platform == "win32"
        platform = "windows-x64" if windows else "linux-x86_64-ubuntu24.04"
        binary = bytearray((seed / ("widevinecdm.dll" if windows else "libwidevinecdm.so")).read_bytes())
        if windows:
            binary[87] = 0
        executable = staging / "bin" / ("helium_drm_fixer.exe" if windows else "helium_drm_fixer")
        executable.parent.mkdir()
        executable.write_bytes(binary)
        for name in ("README.md", "LICENSE", "licenses/nlohmann-json-MIT.txt", "licenses/miniz-MIT.txt"):
            path = staging / SHARE / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic release test\n", encoding="utf-8")
        output = root / "output"
        output.mkdir()
        paths = build_release(staging, "1.2.3", platform, output, key, args.openssl)
        package, manifest, signature = paths
        original_package, original_manifest, original_signature = (path.read_bytes() for path in paths)

        def verify(name, *, trust=public, expected="1.2.3", accepted=True):
            nonlocal passed
            result = subprocess.run([str(helper), "--verify-app-package", str(manifest),
                                     str(signature), str(trust), str(package), expected],
                                    capture_output=True, timeout=15)
            if (result.returncode == 0) != accepted:
                raise RuntimeError(f"{name}: exit {result.returncode}: {result.stderr!r}")
            passed += 1
            print(f"{name}: passed", flush=True)

        def rejected(name, action):
            nonlocal passed
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            try:
                action()
            except (ValueError, OSError):
                pass
            else:
                raise RuntimeError(f"{name}: unsafe release accepted")
            if {path.name: path.read_bytes() for path in output.iterdir()} != before:
                raise RuntimeError(f"{name}: changed existing release output")
            passed += 1
            print(f"{name}: passed", flush=True)

        verify("RSA-3072 manifest and ZIP digest")
        verify("untrusted signing key", trust=other_public, accepted=False)
        verify("unexpected app version", expected="1.2.4", accepted=False)
        package.write_bytes(original_package[:-1] + bytes([original_package[-1] ^ 1]))
        verify("changed ZIP bytes", accepted=False)
        package.write_bytes(original_package[:-1])
        verify("truncated ZIP", accepted=False)
        package.write_bytes(original_package)
        signature.write_bytes(original_signature[:-1] + bytes([original_signature[-1] ^ 1]))
        verify("changed signature", accepted=False)
        signature.write_bytes(original_signature[:-1])
        verify("truncated signature", accepted=False)
        signature.write_bytes(original_signature)
        manifest.write_bytes(original_manifest + b" ")
        verify("manifest exact bytes matter", accepted=False)
        manifest.write_bytes(original_manifest)
        raw_signature = command([args.openssl, "dgst", "-sha256", "-sign", key.name], original_manifest)
        signature.write_bytes(raw_signature)
        verify("signature domain separation", accepted=False)
        signature.write_bytes(original_signature)
        for change in range(12):
            value = json.loads(original_manifest)
            if change == 0: value["repository"] = "other/repo"
            if change == 1: value["app_id"] = "other"
            if change == 2: value["platform"] = "other-platform"
            if change == 3: value["files"][0]["path"] = "../escape"
            if change == 4: value["files"].append(value["files"][0].copy())
            if change == 5: value["files"].pop()
            if change == 6: value["package"]["size"] = -1
            if change == 7: value["package"]["name"] = "wrong.zip"
            if change == 8: value["schema_version"] = 1.0
            if change == 9: value["files"][0]["executable"] = False
            if change == 10: value["files"][0]["size"] = 0
            if change == 11: value["package"]["sha256"] = value["package"]["sha256"].upper()
            changed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            manifest.write_bytes(changed)
            signature.write_bytes(sign_manifest(changed, key, args.openssl))
            verify(f"signed invalid manifest {change}", accepted=False)
        manifest.write_bytes(original_manifest)
        signature.write_bytes(original_signature)
        weak, weak_public = root / "weak.pem", root / "weak.der"
        generate(2048, weak, weak_public)
        signature.write_bytes(command([args.openssl, "dgst", "-sha256", "-sign", weak.name], DOMAIN + original_manifest))
        verify("weak RSA key rejected natively", trust=weak_public, accepted=False)
        rejected("weak RSA signer rejected", lambda: sign_manifest(original_manifest, weak, args.openssl))
        strong, strong_public = root / "strong.pem", root / "strong.der"
        generate(4096, strong, strong_public)
        signature.write_bytes(sign_manifest(original_manifest, strong, args.openssl))
        verify("RSA-4096 signature", trust=strong_public)
        signature.write_bytes(original_signature)
        trailing = root / "trailing.der"
        trailing.write_bytes(public.read_bytes() + b"\0")
        verify("trailing public key data", trust=trailing, accepted=False)
        ec, ec_public = root / "ec.pem", root / "ec.der"
        command([args.openssl, "genpkey", "-algorithm", "EC", "-pkeyopt",
                 "ec_paramgen_curve:prime256v1", "-out", ec.name])
        ec_public.write_bytes(command([args.openssl, "pkey", "-in", ec.name,
                                       "-pubout", "-outform", "DER"]))
        signature.write_bytes(command([args.openssl, "dgst", "-sha256", "-sign", ec.name], DOMAIN + original_manifest))
        verify("EC key cannot substitute for RSA", trust=ec_public, accepted=False)
        rejected("EC signer rejected", lambda: sign_manifest(original_manifest, ec, args.openssl))
        signature.write_bytes(original_signature)
        state = command([str(helper), "--app-update-trust"]).strip()
        if state == b"disabled":
            result = subprocess.run([str(helper), "--verify-app-package-configured",
                                     str(manifest), str(signature), str(package), "1.2.3"],
                                    capture_output=True, timeout=15)
            if result.returncode == 0:
                raise RuntimeError("Unconfigured application trusted a test signing key")
            passed += 1
            print("unconfigured app rejects signed updates: passed", flush=True)

        repeat = root / "repeat"
        repeat.mkdir()
        repeated = build_release(staging, "1.2.3", platform, repeat, key, args.openssl)
        if [path.read_bytes() for path in repeated] != [original_package, original_manifest, original_signature]:
            raise RuntimeError("Identical staging did not produce identical release files")
        with zipfile.ZipFile(package) as archive:
            content = json.loads(original_manifest)
            if set(archive.namelist()) != {file["path"] for file in content["files"]}:
                raise RuntimeError("ZIP and manifest inventories differ")
            for file in content["files"]:
                data = archive.read(file["path"])
                mode = archive.getinfo(file["path"]).external_attr >> 16
                if hashlib.sha256(data).hexdigest() != file["sha256"] or len(data) != file["size"] or bool(mode & 0o111) != file["executable"]:
                    raise RuntimeError("ZIP inventory, permissions or hash mismatch")
        passed += 1
        print("deterministic archive and signed inventory: passed", flush=True)
        rejected("existing release is not overwritten", lambda: build_release(staging, "1.2.3", platform, output))
        rejected("invalid version", lambda: build_release(staging, "01.2.3", platform, output))
        unknown = staging / "private.pem"
        unknown.write_text("must never enter an archive", encoding="ascii")
        rejected("unlisted staged file", lambda: build_release(staging, "1.2.3", platform, output))
        unknown.unlink()
        alias = root / "binary-alias"
        os.link(executable, alias)
        rejected("hardlinked staged file", lambda: build_release(staging, "1.2.3", platform, output))
        alias.unlink()
        if not windows:
            alias.symlink_to(staging, target_is_directory=True)
            rejected("symlinked staging root", lambda: build_release(alias, "1.2.3", platform, output))
            alias.unlink()
        else:
            command(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(staging)])
            rejected("junction staging root", lambda: build_release(alias, "1.2.3", platform, output))
            alias.rmdir()
        encrypted = root / "encrypted.pem"
        os.environ["FIXER_TEST_KEY_PASSWORD"] = "temporary test-only passphrase"
        try:
            command([args.openssl, "pkey", "-in", key.name, "-aes-256-cbc", "-passout",
                     "env:FIXER_TEST_KEY_PASSWORD", "-out", encrypted.name])
            signed = sign_manifest(original_manifest, encrypted, args.openssl, "FIXER_TEST_KEY_PASSWORD")
            if signed != original_signature:
                raise RuntimeError("Encrypted private key produced a different signature")
        finally:
            os.environ.pop("FIXER_TEST_KEY_PASSWORD", None)
        passed += 1
        print("encrypted signing key via passphrase environment: passed", flush=True)
    print(f"{passed} signed release scenarios passed; no key or package installed")


if __name__ == "__main__":
    main()
