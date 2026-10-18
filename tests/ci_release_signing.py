"""Check CI provenance gates and secret handling with an ephemeral release key."""

import argparse
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ci_release_signing as signing
from package_app_release import DOMAIN, SHARE, build_release


class ProvenanceTests(unittest.TestCase):
    def test_download_uses_triggering_build_commit(self):
        # workflow_run's GITHUB_SHA may already point to a newer main commit.
        sha = "a" * 40
        repository = {"full_name": signing.REPOSITORY}
        run = {"id": 123, "status": "completed", "conclusion": "success", "event": "push",
               "head_branch": "main", "head_sha": sha, "path": ".github/workflows/build.yml",
               "repository": repository, "head_repository": repository}
        environment = {"BUILD_RUN_ID": "123", "BUILD_SOURCE_SHA": sha,
                       "GITHUB_SHA": "b" * 40, "GITHUB_REF": "refs/heads/main",
                       "GITHUB_REPOSITORY": signing.REPOSITORY}
        with tempfile.TemporaryDirectory(prefix="helium-ci-provenance-") as temporary, \
                patch.dict(os.environ, environment), patch.object(signing, "INPUT", Path(temporary) / "input"), \
                patch.object(signing.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(run))) as command, \
                patch.object(signing, "candidates"), patch.object(signing, "project_version", return_value="0.1.1"):
            signing.download()
            downloads = [call.args[0] for call in command.call_args_list[1:]]
            self.assertEqual(len(downloads), 2)
            self.assertTrue(all(args[:4] == ["gh", "run", "download", "123"] for args in downloads))

    def test_run_provenance(self):
        sha = "a" * 40
        repository = {"full_name": signing.REPOSITORY}
        run = {"id": 123, "status": "completed", "conclusion": "success", "event": "push",
               "head_branch": "main", "head_sha": sha, "path": ".github/workflows/build.yml",
               "repository": repository, "head_repository": repository}
        signing.validate_run(run, "123", signing.REPOSITORY, sha)
        for field, bad in (("id", 124), ("conclusion", "failure"), ("status", "in_progress"),
                           ("event", "pull_request"), ("event", "workflow_dispatch"),
                           ("head_branch", "other"), ("head_sha", "b" * 40),
                           ("path", ".github/workflows/other.yml"),
                           ("repository", {"full_name": "other/fork"}),
                           ("head_repository", {"full_name": "other/fork"})):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                changed = copy.deepcopy(run)
                changed[field] = bad
                signing.validate_run(changed, "123", signing.REPOSITORY, sha)
        for run_id in ("0", "-1", "123;echo secret", "123/../456"):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                signing.validate_run(run, run_id, signing.REPOSITORY, sha)

    def test_signing_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="helium-ci-signing-test-") as temporary:
            root = Path(temporary)
            key = root / "ephemeral.pem"
            public = root / "keys" / "app-update-public.der"
            public.parent.mkdir()
            password = "ephemeral test passphrase"
            with patch.dict(os.environ, {"TEST_KEY_PASSWORD": password}):
                subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                                "rsa_keygen_bits:3072", "-aes-256-cbc", "-pass", "env:TEST_KEY_PASSWORD",
                                "-out", key.name], cwd=root, capture_output=True, check=True, timeout=60)
                derived = subprocess.run([OPENSSL, "pkey", "-in", key.name, "-passin",
                                          "env:TEST_KEY_PASSWORD", "-pubout", "-outform", "DER"],
                                         cwd=root, capture_output=True, check=True, timeout=20)
            public.write_bytes(derived.stdout)
            inputs = root / "inputs"
            inputs.mkdir()
            originals = {}
            for platform in signing.ARTIFACTS:
                windows = platform == "windows-x64"
                staging = root / ("staging-" + platform)
                executable = staging / "bin" / ("helium_drm_fixer.exe" if windows else "helium_drm_fixer")
                executable.parent.mkdir(parents=True)
                binary = bytearray(128)
                if windows:
                    binary[:2] = b"MZ"
                    binary[60:64] = (64).to_bytes(4, "little")
                    binary[64:70] = b"PE\0\0\x64\x86"
                    binary[88:90] = b"\x0b\x02"
                else:
                    binary[:7] = b"\x7fELF\x02\x01\x01"
                    binary[16:20] = b"\x02\0\x3e\0"
                executable.write_bytes(binary)
                for name in ("README.md", "LICENSE", "licenses/nlohmann-json-MIT.txt", "licenses/miniz-MIT.txt"):
                    path = staging / SHARE / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("Synthetic test license\n", encoding="utf-8")
                folder = inputs / platform
                folder.mkdir()
                paths = build_release(staging, "0.1.1", platform, folder)
                originals[platform] = {path.name: path.read_bytes() for path in paths}
            pem = key.read_text(encoding="ascii")
            secrets = {"RELEASE_SIGNING_KEY_PEM": pem, "RELEASE_SIGNING_KEY_PASSPHRASE": password}
            outputs = root / "signed"
            with patch.object(signing, "ROOT", root), patch.object(signing, "INPUT", inputs), \
                    patch.object(signing, "OUTPUT", outputs), patch.object(signing, "project_version", return_value="0.1.1"):
                # A damaged second platform must fail before touching any private key.
                second = inputs / "linux-x86_64-ubuntu24.04"
                zip_path = next(second.glob("*.zip"))
                original_zip = zip_path.read_bytes()
                zip_path.write_bytes(original_zip + b"tampered")
                with patch.dict(os.environ, secrets), patch.object(signing.tempfile, "TemporaryDirectory") as factory:
                    with self.assertRaises(ValueError):
                        signing.sign(OPENSSL)
                    factory.assert_not_called()
                zip_path.write_bytes(original_zip)
                temporary_keys = []
                original_factory = tempfile.TemporaryDirectory

                def record_directory(*args, **kwargs):
                    directory = original_factory(*args, **kwargs)
                    temporary_keys.append(Path(directory.name))
                    return directory

                with patch.dict(os.environ, secrets), \
                        patch.object(signing.tempfile, "TemporaryDirectory", side_effect=record_directory):
                    signing.sign(OPENSSL)
                    self.assertNotIn("RELEASE_SIGNING_KEY_PEM", os.environ)
                    self.assertNotIn("RELEASE_SIGNING_KEY_PASSPHRASE", os.environ)
                self.assertTrue(temporary_keys)
                self.assertTrue(all(not directory.exists() for directory in temporary_keys))
                files = [path for path in outputs.rglob("*") if path.is_file()]
                self.assertEqual(len(files), 8)
                notes = (outputs / "release-notes.md").read_text(encoding="utf-8")
                self.assertIn("/releases/download/v0.1.1/helium_drm_fixer.exe", notes)
                self.assertLess(notes.index("herunterladen (.exe)"), notes.index("<details>"))
                with zipfile.ZipFile(io.BytesIO(next(
                        data for name, data in originals["windows-x64"].items() if name.endswith(".zip")))) as archive:
                    self.assertEqual((outputs / "windows-x64" / "helium_drm_fixer.exe").read_bytes(),
                                     archive.read("bin/helium_drm_fixer.exe"))
                for platform, original in originals.items():
                    for name, data in original.items():
                        self.assertEqual((outputs / platform / name).read_bytes(), data)
                    manifest = next((outputs / platform).glob("*.manifest.json"))
                    signature = manifest.with_suffix(".sig")
                    subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", str(public), "-keyform", "DER",
                                    "-signature", str(signature), "-sigopt", "rsa_padding_mode:pkcs1"],
                                   input=DOMAIN + manifest.read_bytes(), capture_output=True, check=True, timeout=20)
                with patch.dict(os.environ, secrets), self.assertRaises(ValueError):
                    signing.sign(OPENSSL)
                # OpenSSL failure must also remove the temporary key and password.
                bad_secrets = dict(secrets, RELEASE_SIGNING_KEY_PASSPHRASE="wrong test password")
                failed_output = root / "failed-signing"
                with patch.dict(os.environ, bad_secrets), patch.object(signing, "OUTPUT", failed_output), \
                        patch.object(signing.tempfile, "TemporaryDirectory", side_effect=record_directory):
                    with self.assertRaises(ValueError):
                        signing.sign(OPENSSL)
                    self.assertNotIn("RELEASE_SIGNING_KEY_PEM", os.environ)
                    self.assertNotIn("RELEASE_SIGNING_KEY_PASSPHRASE", os.environ)
                self.assertTrue(all(not directory.exists() for directory in temporary_keys))
                self.assertEqual(list(failed_output.iterdir()), [])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    OPENSSL = str(Path(args.openssl).resolve())
    unittest.main(argv=[sys.argv[0]])
