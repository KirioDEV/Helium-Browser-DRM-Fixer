"""Verify signed releases and test online update/restore in a new isolated folder.

Without --run, only prepare the test. Keeps reports, jobs and backups on failure.
Never changes a browser installation or publishes a release.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
import time
import zipfile

from package_app_release import LIMIT, REPOSITORY, read_regular, version_parts


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(read_regular(path, LIMIT)).hexdigest()


def check_windows_paths(directory, file_paths):
    """Budget the native 240 UTF-16-unit limit, including nested staging files."""
    directory = PureWindowsPath(directory)
    identifier = "0" * 32
    jobs = directory / ".helium-app-update-jobs"
    staging = jobs / ("app-update-" + identifier + ".partial")
    job = jobs / ("job-" + identifier)
    state = directory / ".helium-app-update"
    paths = [staging / filename for filename in file_paths]
    paths += [staging / "app-update.manifest.json", staging / "app-update.manifest.sig",
              job / "update-helper.exe", job / ("decision.json.tmp-" + identifier),
              job / ("status.json.tmp-" + identifier), state / ("journal.json.tmp-" + identifier),
              state / ("history-" + identifier + ".json.tmp-" + identifier)]
    longest = max(len(str(path).encode("utf-16-le")) // 2 for path in paths)
    require(longest <= 240,
            f"Windows test paths need {longest} UTF-16 characters (limit 240). "
            "Choose a shorter --output directory, for example build/smoke-12345678.")


class SmokeTest:
    def __init__(self, verifier, baseline, candidate, output, timeout=60):
        self.verifier = Path(verifier).resolve(strict=True)
        self.baseline = Path(baseline).absolute()
        self.candidate = Path(candidate).absolute()
        self.root = Path(output).absolute()
        require(not os.path.lexists(self.root), "Choose a new, nonexistent output directory")
        require(self.root.parent.is_dir(), "Output parent directory must exist")
        require(sys.platform in ("win32", "linux"), "Run natively on Windows or Linux")
        self.root.mkdir(mode=0o700)
        self.target = self.root / "app" / ("helium_drm_fixer.exe" if sys.platform == "win32" else "helium_drm_fixer")
        self.timeout = timeout
        self.report = {"schema_version": 1, "state": "preparing", "repository": REPOSITORY,
                       "directory": str(self.root), "target": str(self.target), "commands": []}
        self.save()

    def save(self):
        temporary = self.root / "report.json.tmp"
        temporary.write_text(json.dumps(self.report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.root / "report.json")

    def invoke(self, executable, *arguments, timeout=180):
        command = [str(executable), *(str(argument) for argument in arguments)]
        result = subprocess.run(command, capture_output=True, timeout=timeout, cwd=self.root)
        entry = {"command": command, "exit_code": result.returncode,
                 "stdout": result.stdout.decode("utf-8", errors="replace"),
                 "stderr": result.stderr.decode("utf-8", errors="replace")}
        self.report["commands"].append(entry)
        self.save()
        return entry

    def json_command(self, executable, *arguments):
        entry = self.invoke(executable, *arguments)
        try:
            value = json.loads(entry["stdout"])
        except (ValueError, RecursionError) as error:
            raise ValueError("Command did not return JSON; inspect report.json") from error
        require(isinstance(value, dict), "Expected JSON object")
        return entry["exit_code"], value

    def inspect(self, package):
        code, value = self.json_command(self.verifier, "--verify-app-release", package, "--json")
        require(code == 0 and value.get("state") == "verified" and value.get("package_verified") is True and
                value.get("installation_performed") is False and value.get("repository") == REPOSITORY,
                "Native signed package verification failed; inspect report.json")
        expected_platform = "windows-x64" if sys.platform == "win32" else "linux-x86_64-ubuntu24.04"
        require(value.get("platform") == expected_platform and value.get("package_name") == package.name,
                "Wrong package name/platform")
        version_parts(value["version"])
        # Bind subsequent extraction to the exact ZIP verified by the native app.
        data = read_regular(package, LIMIT)
        require(hashlib.sha256(data).hexdigest() == value["package_sha256"],
                "Package changed after native verification")
        return value, data

    def version(self, expected):
        entry = self.invoke(self.target, "--version")
        require(entry["exit_code"] == 0 and entry["stdout"].strip() == expected,
                "Unexpected executable version; inspect report.json")

    def prepare(self):
        old, old_bytes = self.inspect(self.baseline)
        new, _ = self.inspect(self.candidate)
        require(tuple(map(int, new["version"].split("."))) > tuple(map(int, old["version"].split("."))),
                "Candidate version must be newer than baseline")
        binary_path = "bin/" + self.target.name
        self.report.update({"baseline": old, "candidate": new})
        if sys.platform == "win32":
            check_windows_paths(self.target.parent, new["files"])
        with zipfile.ZipFile(io.BytesIO(old_bytes)) as archive:
            binary = archive.read(binary_path)
        require(hashlib.sha256(binary).hexdigest() == old["files"][binary_path],
                "Baseline executable hash mismatch")
        self.target.parent.mkdir(mode=0o700)
        with self.target.open("xb") as stream:
            stream.write(binary)
        self.target.chmod(0o700)
        self.version(old["version"])
        self.report["state"] = "prepared"
        self.save()

    def scheduled_job(self, executable, *arguments):
        entry = self.invoke(executable, *arguments)
        detail = entry["stderr"].strip() or entry["stdout"].strip()
        require(entry["exit_code"] == 0, "Scheduling failed: " + detail + "; inspect report.json")
        jobs = re.findall(r"^Job: (.+)$", entry["stdout"], re.MULTILINE)
        helpers = re.findall(r"^Recovery helper: (.+)$", entry["stdout"], re.MULTILINE)
        require(len(jobs) == len(helpers) == 1, "Missing job/recovery helper output")
        job, helper = Path(jobs[0].strip()), Path(helpers[0].strip())
        require(job.is_absolute() and job.parent == self.target.parent / ".helium-app-update-jobs" and
                re.fullmatch(r"job-[0-9a-f]{32}", job.name) is not None,
                "Job is outside the isolated test directory")
        name = "update-helper.exe" if sys.platform == "win32" else "update-helper"
        require(helper == job / name and not helper.is_symlink(), "Unexpected recovery helper")
        # Never execute a helper unless it is an exact copy of the trusted baseline.
        require(digest(helper) == self.report["baseline"]["files"]["bin/" + self.target.name],
                "Recovery helper differs from the verified baseline")
        return job, helper

    def wait(self, job, helper, wanted):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            code, value = self.json_command(helper, "--app-update-status", job, "--json")
            if value.get("state") == wanted:
                require(code == 0 and value.get("exit_code") == 0, "Operation returned an error")
                return value
            require(code == 0 and value.get("state") in ("waiting_for_parent", "applying"),
                    "Helper failed or returned an unexpected state; inspect report.json")
            time.sleep(0.2)
        raise ValueError("Helper timed out; keep job and recovery helper for inspection")

    def exercise(self):
        old, new = self.report["baseline"], self.report["candidate"]
        code, offer = self.json_command(self.target, "--check-app-update", "--json")
        self.report["offer"] = offer
        self.save()
        require(code == 0 and offer.get("state") == "update_available" and
                offer.get("self_install_supported") is True and offer.get("repository") == REPOSITORY and
                offer.get("installed_version") == old["version"] and
                offer.get("available_version") == new["version"] and offer.get("package_name") == self.candidate.name,
                "Expected newer stable release is not offered (or build cannot self-update); inspect report.json")
        job, helper = self.scheduled_job(self.target, "--update-app")
        self.report.update({"state": "updating", "update_job": str(job), "recovery_helper": str(helper)})
        self.save()
        self.report["update_status"] = self.wait(job, helper, "installed")
        self.save()
        try:
            actual = digest(self.target)
            self.report["installed_sha256"] = actual
            require(actual == new["files"]["bin/" + self.target.name],
                    "Installed executable differs from verified candidate; refusing to execute it")
            self.version(new["version"])
            self.report["update_verified"] = True
        finally:
            # Use the old, verified helper even if the new executable is damaged.
            # Do not attempt restore while an update is still running or unknown.
            restore_job, restore_helper = self.scheduled_job(helper, "--restore-app", self.target)
            self.report.update({"state": "restoring", "restore_job": str(restore_job),
                                "restore_helper": str(restore_helper)})
            self.save()
            self.report["restore_status"] = self.wait(restore_job, restore_helper, "restored")
            actual = digest(self.target)
            self.report["restored_sha256"] = actual
            require(actual == old["files"]["bin/" + self.target.name],
                    "Restored executable does not match baseline; inspect report.json")
            self.version(old["version"])
            self.report["restore_verified"] = True
            self.save()
        self.report["state"] = "passed"
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True, help="Existing trusted native app with public key")
    parser.add_argument("--baseline", type=Path, required=True, help="Signed older standalone app ZIP")
    parser.add_argument("--candidate", type=Path, required=True, help="Signed newer native app ZIP")
    parser.add_argument("--output", type=Path, required=True, help="New test directory; parent must exist")
    parser.add_argument("--run", action="store_true", help="Perform online update and restore after preparation")
    args = parser.parse_args()
    test = None
    try:
        test = SmokeTest(args.verifier, args.baseline, args.candidate, args.output)
        test.prepare()
        if args.run:
            test.exercise()
        print(f"{test.report['state']}: {test.root / 'report.json'}")
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        if test is not None:
            test.report.update({"state": "failed", "error": str(error)})
            test.save()
            print(f"Test files retained: {test.root}", file=sys.stderr)
        parser.exit(1, f"App update smoke test failed: {error}\n")


if __name__ == "__main__":
    main()
