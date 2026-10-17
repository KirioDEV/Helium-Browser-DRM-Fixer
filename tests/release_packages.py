"""Cross-check release packaging/signatures with the native Windows/Linux verifier."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from package_app_release import DOMAIN, SHARE, build_release, sign_manifest
from cli_integration import source
from app_transactions import exercise_app_transactions
from app_processes import exercise_process_handoff
from candidate_signing import exercise_candidate_signing


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--process-helper", type=Path)
    parser.add_argument("--program", type=Path)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--staging-space", type=Path,
                        help="Optional private parent on a bounded filesystem (<2 MiB free)")
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
        passed += exercise_candidate_signing(helper, args.program.resolve() if args.program else None,
                                            root, package, public, key, other_key, args.openssl)

        def stage_case(name, parent, *, accepted=False, cancelled=False):
            nonlocal passed
            mode = "--stage-app-package-cancelled" if cancelled else "--stage-app-package"
            result = subprocess.run([str(helper), mode, str(manifest), str(signature),
                                     str(public), str(package), "1.2.3", str(parent)],
                                    capture_output=True, timeout=15)
            if (result.returncode == 0) != accepted or (cancelled and result.returncode != 130):
                raise RuntimeError(f"{name}: exit {result.returncode}: {result.stderr!r}")
            passed += 1
            print(f"{name}: passed", flush=True)
            return Path(result.stdout.decode("utf-8").strip()) if accepted else None

        stage_parent = root / "private update staging"
        command([str(helper), "--create-private-app-staging", str(stage_parent)])
        sentinel = stage_parent / "existing.txt"
        sentinel.write_bytes(b"leave existing app/staging files alone")
        ready = stage_case("private app staging", stage_parent, accepted=True)
        if ready.parent != stage_parent or not ready.name.endswith(".ready"):
            raise RuntimeError("Staging was published outside the requested parent")
        expected_files = json.loads(original_manifest)["files"]
        actual_files = {path.relative_to(ready).as_posix() for path in ready.rglob("*") if path.is_file()}
        if actual_files != {file["path"] for file in expected_files}:
            raise RuntimeError("Staged file inventory differs")
        for file in expected_files:
            path = ready / file["path"]
            if hashlib.sha256(path.read_bytes()).hexdigest() != file["sha256"]:
                raise RuntimeError("Staged file bytes differ")
            if not windows and path.stat().st_mode & 0o777 != (0o700 if file["executable"] else 0o600):
                raise RuntimeError("Staged file is not private or has incorrect executable mode")
        if not windows:
            for path in [ready, *(path for path in ready.rglob("*") if path.is_dir())]:
                if path.stat().st_mode & 0o777 != 0o700:
                    raise RuntimeError("Staged directory is not private")
        before = {path.relative_to(stage_parent): path.read_bytes()
                  for path in stage_parent.rglob("*") if path.is_file()}
        second_stage = stage_case("independent second app staging", stage_parent, accepted=True)
        if second_stage == ready or sentinel.read_bytes() != b"leave existing app/staging files alone":
            raise RuntimeError("Staging reused or changed an existing entry")
        if any((stage_parent / name).read_bytes() != data for name, data in before.items()):
            raise RuntimeError("Second staging modified earlier files")
        before_names = set(stage_parent.iterdir())
        stage_case("cancelled staging creates nothing", stage_parent, cancelled=True)
        package.write_bytes(original_package[:-1])
        stage_case("invalid package creates nothing", stage_parent)
        package.write_bytes(original_package)
        if set(stage_parent.iterdir()) != before_names:
            raise RuntimeError("Cancelled or invalid staging created files")
        missing_parent = root / "missing staging parent"
        stage_case("missing staging parent is not created", missing_parent)
        if missing_parent.exists():
            raise RuntimeError("Staging created its missing parent")
        stage_case("relative staging parent rejected", Path("relative-staging"))
        if not windows:
            public_parent = root / "public staging parent"
            public_parent.mkdir(mode=0o755)
            public_parent.chmod(0o755)
            stage_case("nonprivate staging parent rejected", public_parent)
            if list(public_parent.iterdir()):
                raise RuntimeError("Nonprivate staging parent was modified")
        stage_link = root / "linked staging parent"
        if windows:
            command(["cmd.exe", "/d", "/c", "mklink", "/J", str(stage_link), str(stage_parent)])
        else:
            stage_link.symlink_to(stage_parent, target_is_directory=True)
        try:
            stage_case("linked staging parent rejected", stage_link)
        finally:
            if windows: stage_link.rmdir()
            else: stage_link.unlink()

        if args.staging_space:
            if windows:
                raise RuntimeError("The bounded filesystem probe currently targets Linux")
            limited = args.staging_space.resolve() / ("stage-probe-" + os.urandom(8).hex())
            command([str(helper), "--create-private-app-staging", str(limited)])
            readme = staging / SHARE / "README.md"
            small_readme = readme.read_bytes()
            readme.write_bytes(b"x" * (2 * 1024 * 1024))
            large_output = root / "large output"
            large_output.mkdir()
            large_paths = build_release(staging, "1.2.3", platform, large_output, key, args.openssl)
            readme.write_bytes(small_readme)
            for destination, candidate in zip(paths, large_paths):
                destination.write_bytes(candidate.read_bytes())
            stage_case("full filesystem does not publish staging", limited)
            children = list(limited.iterdir())
            if not children or any(not path.name.endswith(".partial") for path in children):
                raise RuntimeError("Failed write published staging or did not exercise partial writes")
            # Only this probe's newly created directory is removed; never the
            # supplied mount/parent or pre-existing data on the test filesystem.
            import shutil
            if limited.parent != args.staging_space.resolve() or not limited.name.startswith("stage-probe-"):
                raise RuntimeError("Refusing cleanup outside this filesystem probe")
            shutil.rmtree(limited)
            for destination, data in zip(paths, (original_package, original_manifest, original_signature)):
                destination.write_bytes(data)

        download_release = root / "download release.json"
        download_config = root / "download config.json"
        base = "https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases/download/v1.2.3/"
        urls = [base + path.name for path in paths]
        download_metadata = {"tag_name": "v1.2.3", "draft": False, "prerelease": False,
                             "html_url": "https://github.com/KirioDEV/Helium-Browser-DRM-Fixer/releases/tag/v1.2.3",
                             "assets": [{"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                                         "browser_download_url": url} for path, url in zip(paths, urls)]}

        def download_case(name, *, accepted=False, expected_requests=(), metadata=None, **options):
            nonlocal passed
            before = set(stage_parent.iterdir())
            download_release.write_text(json.dumps(download_metadata if metadata is None else metadata), encoding="utf-8")
            download_config.write_text(json.dumps({"release": str(download_release), "parent": str(stage_parent),
                                                   "key": str(public), "assets": {url: str(path) for path, url in zip(paths, urls)},
                                                   **options}), encoding="utf-8")
            result = subprocess.run([str(helper), "--download-app-fixture", str(download_config)],
                                    capture_output=True, timeout=15)
            status = json.loads(result.stdout)
            if (result.returncode == 0) != accepted or status["requests"] != list(expected_requests):
                raise RuntimeError(f"{name}: unexpected download result {result.returncode}: {status}: {result.stderr!r}")
            if not accepted and set(stage_parent.iterdir()) != before:
                raise RuntimeError(f"{name}: failed download changed staging parent")
            if accepted and not Path(status["directory"]).is_dir():
                raise RuntimeError(f"{name}: did not publish prepared package")
            passed += 1
            print(f"{name}: passed", flush=True)
            return Path(status["directory"]) if accepted else None

        sequence = (urls[1], urls[2], urls[0])
        handoff = download_case("verified download to private staging", accepted=True, expected_requests=sequence)
        if (handoff / "app-update.manifest.json").read_bytes() != original_manifest or (handoff / "app-update.manifest.sig").read_bytes() != original_signature:
            raise RuntimeError("Prepared update did not preserve exact signed metadata")

        def read_handoff(name, *, path=handoff, key=public, version="1.2.3", accepted=False, configured=False):
            nonlocal passed
            before = {item.relative_to(handoff): item.read_bytes() for item in handoff.rglob("*") if item.is_file() and not item.is_symlink()}
            arguments = [str(helper), "--read-app-handoff-configured", str(path), version] if configured else [str(helper), "--read-app-handoff", str(path), str(key), version]
            result = subprocess.run(arguments, capture_output=True, timeout=15)
            if (result.returncode == 0) != accepted:
                raise RuntimeError(f"{name}: exit {result.returncode}: {result.stderr!r}")
            if accepted:
                status = json.loads(result.stdout)
                expected = {file["path"]: file["sha256"] for file in expected_files}
                if status["files"] != expected or status["version"] != "1.2.3":
                    raise RuntimeError("Reloaded handoff bytes differ from signed inventory")
            after = {item.relative_to(handoff): item.read_bytes() for item in handoff.rglob("*") if item.is_file() and not item.is_symlink()}
            if before != after:
                raise RuntimeError("Handoff reload changed staged files")
            passed += 1
            print(f"{name}: passed", flush=True)

        read_handoff("fresh process revalidates persisted handoff", accepted=True)
        read_handoff("handoff rejects foreign signing key", key=other_public)
        read_handoff("handoff rejects incorrect expected version", version="1.2.4")
        read_handoff("handoff rejects downgrade", version="0.0.1")
        read_handoff("handoff uses compiled trust only", configured=True)
        manifest_file = handoff / "app-update.manifest.json"
        signature_file = handoff / "app-update.manifest.sig"
        manifest_file.write_bytes(original_manifest + b" ")
        read_handoff("handoff detects changed manifest")
        manifest_file.write_bytes(original_manifest)
        signature_file.write_bytes(original_signature[:-1])
        read_handoff("handoff detects truncated signature")
        signature_file.write_bytes(original_signature)
        signature_file.rename(handoff / "missing.sig")
        read_handoff("handoff rejects partial metadata")
        (handoff / "missing.sig").rename(signature_file)
        staged_binary = handoff / executable.relative_to(staging)
        staged_binary.write_bytes(bytes(binary[:-1]) + bytes([binary[-1] ^ 1]))
        read_handoff("handoff detects changed executable")
        staged_binary.write_bytes(binary)
        unlisted = handoff / "unlisted.txt"
        unlisted.write_bytes(b"unexpected")
        read_handoff("handoff rejects additional file")
        unlisted.unlink()
        unlisted.mkdir()
        read_handoff("handoff rejects additional empty directory")
        unlisted.rmdir()
        readme_file = handoff / SHARE / "README.md"
        readme_file.unlink()
        read_handoff("handoff rejects missing signed file")
        readme_file.write_text("Synthetic release test\n", encoding="utf-8")
        alias = root / "handoff-hardlink"
        os.link(staged_binary, alias)
        read_handoff("handoff rejects hardlinked executable")
        alias.unlink()
        read_handoff("handoff rejects unrelated directory name", path=stage_parent)
        missing_handoff = stage_parent / ("app-update-" + "0" * 32 + ".ready")
        read_handoff("handoff never creates missing directory", path=missing_handoff)
        if missing_handoff.exists():
            raise RuntimeError("Read-only handoff check created its target")
        signature_alias = root / "handoff-signature-hardlink"
        os.link(signature_file, signature_alias)
        read_handoff("handoff rejects hardlinked signature")
        signature_alias.unlink()
        linked_handoff = stage_parent / ("app-update-" + "1" * 32 + ".ready")
        if windows:
            command(["cmd.exe", "/d", "/c", "mklink", "/J", str(linked_handoff), str(handoff)])
        else:
            linked_handoff.symlink_to(handoff, target_is_directory=True)
        try:
            read_handoff("handoff rejects linked root", path=linked_handoff)
        finally:
            if windows: linked_handoff.rmdir()
            else: linked_handoff.unlink()
        if not windows:
            handoff.chmod(0o755)
            try:
                read_handoff("handoff rejects nonprivate root")
            finally:
                handoff.chmod(0o700)
        read_handoff("handoff remains valid after rejected tampering", accepted=True)
        passed += exercise_app_transactions(helper, root, handoff, public, other_public, binary)
        if args.process_helper:
            passed += exercise_process_handoff(args.process_helper.resolve(), helper, root,
                                              handoff, public, other_public, binary,
                                              args.program.resolve() if args.program else None)
        if windows:
            # A correctly signed development package with external runtimes is
            # valid for inspection, but must never be partly self-installed.
            runtime_files = []
            runtime_manifest = json.loads(original_manifest)
            library = bytearray(binary)
            library[87] |= 0x20
            for name in ("libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"):
                path = handoff / "bin" / name
                path.write_bytes(library)
                runtime_files.append(path)
                runtime_manifest["files"].append({
                    "path": "bin/" + name, "size": len(library),
                    "sha256": hashlib.sha256(library).hexdigest(), "executable": False,
                })
            runtime_bytes = json.dumps(runtime_manifest, sort_keys=True, separators=(",", ":")).encode()
            manifest_file.write_bytes(runtime_bytes)
            signature_file.write_bytes(sign_manifest(runtime_bytes, key, args.openssl))
            try:
                command([str(helper), "--read-app-handoff", str(handoff), str(public), "1.2.3"])
                target_parent = root / "runtime package target"
                command([str(helper), "--create-private-app-staging", str(target_parent)])
                target = target_parent / executable.name
                old = bytes(binary) + b"previous application"
                target.write_bytes(old)
                config = root / "runtime transaction.json"
                config.write_text(json.dumps({
                    "target": str(target), "directory": str(handoff), "key": str(public),
                    "old_sha256": hashlib.sha256(old).hexdigest(),
                }), encoding="utf-8")
                result = subprocess.run([str(helper), "--app-transaction-fixture", str(config)],
                                        capture_output=True, timeout=15)
                if result.returncode != 4 or target.read_bytes() != old or set(target_parent.iterdir()) != {target}:
                    raise RuntimeError("App updater partially installed an external-runtime package")
                passed += 1
                print("app replacement rejects signed external-runtime package: passed", flush=True)
            finally:
                manifest_file.write_bytes(original_manifest)
                signature_file.write_bytes(original_signature)
                for path in runtime_files:
                    path.unlink()
        download_case("untrusted download stops before package", key=str(other_public), expected_requests=sequence[:2])
        signature.write_bytes(original_signature[:-1] + bytes([original_signature[-1] ^ 1]))
        download_case("invalid signature stops before package", expected_requests=sequence[:2])
        signature.write_bytes(original_signature)
        changed_metadata = json.loads(json.dumps(download_metadata))
        changed_metadata["assets"][0]["size"] += 1
        download_case("advertised package size must match signature", metadata=changed_metadata, expected_requests=sequence[:2])
        package.write_bytes(original_package[:-1] + bytes([original_package[-1] ^ 1]))
        download_case("corrupt package is never staged", expected_requests=sequence)
        package.write_bytes(original_package)
        changed_metadata = json.loads(json.dumps(download_metadata))
        changed_metadata["assets"].pop()
        download_case("unsigned release triggers no asset requests", metadata=changed_metadata)
        download_case("current app triggers no asset requests", installed="1.2.3")
        download_case("cancelled preparation triggers no asset requests", cancelled=True)
        if command([str(helper), "--app-update-trust"]).strip() == b"disabled":
            download_case("unconfigured trust triggers no asset requests", compiled_trust=True)
        else:
            download_case("configured trust rejects ephemeral download signer", compiled_trust=True,
                          expected_requests=sequence[:2])

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

        verify("RSA-3072 manifest and unpacked ZIP inventory")
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
        # Re-sign the compressed package hash so these cases exercise ZIP and
        # inventory checks after successful signature/digest verification.
        with zipfile.ZipFile(io.BytesIO(original_package)) as archive:
            entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
        for change in range(16):
            value = json.loads(original_manifest)
            stream = io.BytesIO()
            with warnings.catch_warnings(), zipfile.ZipFile(stream, "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for index, (original_entry, original_data) in enumerate(entries):
                    entry = zipfile.ZipInfo(original_entry.filename)
                    entry.create_system = 3
                    entry.external_attr = original_entry.external_attr
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    data = original_data
                    if index == 0:
                        if change == 0: entry.filename = "../escape"
                        if change == 1: entry.filename = entry.filename.upper()
                        if change == 2: entry.external_attr = (0o120755 << 16)
                        if change == 3: entry.external_attr = (0o104755 << 16)
                        if change == 4: entry.external_attr = (0o100644 << 16)
                        if change == 5: data += b"changed"
                        if change == 6: data = bytes([data[0] ^ 1]) + data[1:]
                        if change == 7: continue
                        if change == 8: entry.filename = "bin/unknown.exe"
                        if change == 9: entry.external_attr |= 0x10
                        if change == 10: entry.external_attr = 0
                        if change == 11: entry.filename += "/"
                        if change == 12:
                            data = b"invalid binary".ljust(len(data), b"\0")
                            value["files"][0]["sha256"] = hashlib.sha256(data).hexdigest()
                        if change == 13:
                            data = bytearray(data)
                            if windows: data[68:70] = b"\x4c\x01"
                            else: data[18:20] = b"\x03\0"
                            value["files"][0]["sha256"] = hashlib.sha256(data).hexdigest()
                        if change == 14 and windows:
                            data = bytearray(data)
                            data[87] |= 0x20
                            value["files"][0]["sha256"] = hashlib.sha256(data).hexdigest()
                    archive.writestr(entry, data)
                    if index == 0 and change == 15:
                        archive.writestr(entry, data)
                if change == 14 and not windows:
                    archive.writestr("unlisted.txt", b"unexpected")
            changed_package = stream.getvalue()
            value["package"]["size"] = len(changed_package)
            value["package"]["sha256"] = hashlib.sha256(changed_package).hexdigest()
            changed_manifest = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            package.write_bytes(changed_package)
            manifest.write_bytes(changed_manifest)
            signature.write_bytes(sign_manifest(changed_manifest, key, args.openssl))
            verify(f"signed unsafe ZIP {change}", accepted=False)
        # Stored entries and empty documentation are supported, without making
        # executable files optional or bypassing per-file hashes.
        value = json.loads(original_manifest)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for original_entry, original_data in entries:
                entry = zipfile.ZipInfo(original_entry.filename)
                entry.create_system = 3
                entry.external_attr = original_entry.external_attr
                data = original_data if entry.filename.startswith("bin/") else b""
                archive.writestr(entry, data)
                for file in value["files"]:
                    if file["path"] == entry.filename:
                        file["size"] = len(data)
                        file["sha256"] = hashlib.sha256(data).hexdigest()
        stored = stream.getvalue()
        for broken_crc in (False, True):
            data = bytearray(stored)
            if broken_crc:
                central = data.index(b"PK\x01\x02")
                data[central + 16] ^= 1
            value["package"]["size"] = len(data)
            value["package"]["sha256"] = hashlib.sha256(data).hexdigest()
            changed_manifest = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            package.write_bytes(data)
            manifest.write_bytes(changed_manifest)
            signature.write_bytes(sign_manifest(changed_manifest, key, args.openssl))
            verify("signed ZIP CRC mismatch" if broken_crc else "stored ZIP and empty documentation",
                   accepted=not broken_crc)
        package.write_bytes(original_package)
        manifest.write_bytes(original_manifest)
        signature.write_bytes(original_signature)
        state = command([str(helper), "--app-update-trust"]).strip()
        if state in (b"disabled", b"configured"):
            result = subprocess.run([str(helper), "--verify-app-package-configured",
                                     str(manifest), str(signature), str(package), "1.2.3"],
                                    capture_output=True, timeout=15)
            if result.returncode == 0:
                raise RuntimeError("Application trusted an unrelated test signing key")
            passed += 1
            print("compiled app trust rejects unrelated test signer: passed", flush=True)

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
    print(f"{passed} signed release scenarios passed; temporary keys and synthetic app files only")


if __name__ == "__main__":
    main()
