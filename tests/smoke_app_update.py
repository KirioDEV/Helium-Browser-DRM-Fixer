"""Test the smoke runner's orchestration using inert bytes and a simulated CLI.

Native cryptographic and helper tests remain in signed_app_packages. These tests
do not claim to have performed an online release update.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from package_app_release import REPOSITORY
from smoke_app_update import SmokeTest


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="helium-smoke-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.verifier = self.root / "trusted-verifier"
        self.verifier.write_bytes(b"Inert verifier fixture, never executed")
        self.windows = sys.platform == "win32"
        self.name = "helium_drm_fixer.exe" if self.windows else "helium_drm_fixer"
        self.platform = "windows-x64" if self.windows else "linux-x86_64-ubuntu24.04"
        self.old = b"Inert baseline bytes"
        self.new = b"Inert updated bytes"
        self.inspections = {}
        for version, binary in (("0.1.0", self.old), ("0.1.1", self.new)):
            package = self.root / f"helium-drm-fixer-cpp-{version}-{self.platform}.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("bin/" + self.name, binary)
            self.inspections[str(package)] = {
                "state": "verified", "package_verified": True, "installation_performed": False,
                "repository": REPOSITORY, "platform": self.platform, "package_name": package.name,
                "version": version, "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "files": {"bin/" + self.name: hashlib.sha256(binary).hexdigest()}}
        packages = list(self.inspections)
        self.test = SmokeTest(self.verifier, packages[0], packages[1], self.root / "isolated")
        self.offered_version = "0.1.1"
        self.corrupt_update = False
        self.helper_fails = False
        self.calls = []
        self.jobs = {}

    def command(self, arguments, **kwargs):
        self.calls.append(arguments)
        executable, mode, *rest = arguments
        code = 0
        if mode == "--verify-app-release":
            value = self.inspections[rest[0]]
        elif mode == "--version":
            binary = Path(executable).read_bytes()
            value = "0.1.0" if binary == self.old else "0.1.1"
        elif mode == "--check-app-update":
            value = {"state": "update_available", "self_install_supported": True,
                     "installed_version": "0.1.0", "available_version": self.offered_version,
                     "package_name": self.test.candidate.name, "repository": REPOSITORY}
        elif mode in ("--update-app", "--restore-app"):
            number = len(self.jobs) + 1
            job = self.test.target.parent / ".helium-app-update-jobs" / f"job-{number:032x}"
            job.mkdir(parents=True)
            helper = job / ("update-helper.exe" if self.windows else "update-helper")
            helper.write_bytes(self.old)
            helper.chmod(0o700)
            if mode == "--update-app":
                self.test.target.write_bytes(b"Unexpected bytes" if self.corrupt_update else self.new)
                self.jobs[str(job)] = "failed" if self.helper_fails else "installed"
            else:
                self.assertEqual(Path(rest[0]), self.test.target)
                self.assertNotEqual(Path(executable), self.test.target)
                self.test.target.write_bytes(self.old)
                self.jobs[str(job)] = "restored"
            value = f"App operation scheduled\nJob: {job}\nRecovery helper: {helper}\n"
        elif mode == "--app-update-status":
            state = self.jobs[rest[0]]
            code = 1 if state == "failed" else 0
            value = {"state": state, "exit_code": code, "detail": "Simulated helper result"}
        else:
            self.fail("Unexpected CLI mode: " + mode)
        output = value if isinstance(value, str) else json.dumps(value)
        return subprocess.CompletedProcess(arguments, code, output.encode("utf-8"), b"")

    def test_prepare_is_offline_and_preserves_inputs(self):
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            self.test.prepare()
        self.assertEqual(self.test.report["state"], "prepared")
        self.assertEqual(self.test.target.read_bytes(), self.old)
        self.assertEqual([call[1] for call in self.calls],
                         ["--verify-app-release", "--verify-app-release", "--version"])
        self.assertTrue(self.test.baseline.is_file())
        self.assertTrue(self.test.candidate.is_file())

    def test_update_and_restore_record_hashes(self):
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            self.test.prepare()
            self.test.exercise()
        report = json.loads((self.test.root / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["state"], "passed")
        self.assertTrue(report["update_verified"])
        self.assertTrue(report["restore_verified"])
        self.assertEqual(report["installed_sha256"], hashlib.sha256(self.new).hexdigest())
        self.assertEqual(report["restored_sha256"], hashlib.sha256(self.old).hexdigest())
        self.assertEqual(self.test.target.read_bytes(), self.old)

    def test_changed_release_is_not_installed(self):
        self.offered_version = "0.1.2"
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            self.test.prepare()
            with self.assertRaisesRegex(ValueError, "not offered"):
                self.test.exercise()
        self.assertNotIn("--update-app", [call[1] for call in self.calls])
        self.assertEqual(self.test.target.read_bytes(), self.old)

    def test_bad_updated_hash_is_restored_without_execution(self):
        self.corrupt_update = True
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            self.test.prepare()
            with self.assertRaisesRegex(ValueError, "refusing to execute"):
                self.test.exercise()
        self.assertEqual(self.test.target.read_bytes(), self.old)
        self.assertTrue(self.test.report["restore_verified"])
        self.assertNotIn("update_verified", self.test.report)
        # The only version probes are the trusted baseline before/after restore.
        self.assertEqual(sum(call[1] == "--version" for call in self.calls), 2)

    def test_failed_helper_retains_job_without_parallel_restore(self):
        self.helper_fails = True
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            self.test.prepare()
            with self.assertRaisesRegex(ValueError, "Helper failed"):
                self.test.exercise()
        self.assertTrue(Path(self.test.report["recovery_helper"]).is_file())
        self.assertNotIn("--restore-app", [call[1] for call in self.calls])

    def test_unverified_candidate_is_never_executed(self):
        self.inspections[str(self.test.candidate)]["package_verified"] = False
        with patch("smoke_app_update.subprocess.run", side_effect=self.command):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                self.test.prepare()
        self.assertFalse(self.test.target.exists())


if __name__ == "__main__":
    unittest.main()
