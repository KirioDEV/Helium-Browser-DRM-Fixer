"""Exercise the native helper with a real old fixture and a signed inert payload."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def exercise_process_handoff(process_helper, helper, root, handoff, public, other_public, binary, program=None):
    passed = 0
    windows = sys.platform == "win32"
    name = "helium_drm_fixer.exe" if windows else "helium_drm_fixer"
    helper_name = "update-helper.exe" if windows else "update-helper"
    source = process_helper.read_bytes()
    environment = os.environ.copy()
    environment["FIXER_TEST_APP_TRUST"] = str(public)
    # Local MinGW tests need their development runtimes. Production MSVC builds
    # are static and never copy or install external runtime DLLs.
    environment["PATH"] = str(process_helper.parent) + os.pathsep + environment.get("PATH", "")

    def private(path):
        subprocess.run([str(helper), "--create-private-app-staging", str(path)],
                       capture_output=True, timeout=15, check=True)

    def check(name, condition):
        nonlocal passed
        if not condition:
            raise RuntimeError(name)
        passed += 1
        print(name + ": passed", flush=True)

    def wait_status(job, wanted):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            status_file = job / "status.json"
            if status_file.exists():
                status = json.loads(status_file.read_bytes())
                if status["state"] in wanted:
                    return status
            time.sleep(0.03)
        raise RuntimeError(f"Helper did not reach {wanted}: {job}")

    def launch(case):
        parent = root / ("native app helper " + case)
        private(parent)
        target = parent / name
        shutil.copyfile(process_helper, target)
        if not windows:
            target.chmod(0o700)
        config = parent / "fixture.json"
        config.write_text(json.dumps({"directory": str(handoff), "hold": True}), encoding="utf-8")
        process = subprocess.Popen([str(target), str(config)], env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = process.stdout.readline()
        if not line:
            _, error = process.communicate(timeout=25)
            raise RuntimeError(f"Native fixture did not schedule a helper: {process.returncode}: {error!r}")
        job = Path(json.loads(line)["job"])
        return process, target, job

    def release(process):
        output, error = process.communicate(b"exit\n", timeout=25)
        if process.returncode:
            raise RuntimeError(f"Native parent failed: {process.returncode}: {output!r} {error!r}")

    parent, target, job = launch("install and restore")
    try:
        check("native helper waits for the pinned live parent",
              target.read_bytes() == source and not (target.parent / ".helium-app-update").exists() and
              wait_status(job, {"waiting_for_parent"})["exit_code"] == 0)
        original_request = json.loads((job / "request.json").read_bytes())
        # The live parent's identity is valid except for the one field being
        # changed. Each negative probe runs in a separate private helper copy.
        for change in ("creation time", "parent image", "image hash", "protocol", "trust", "request trust override"):
            probe = job.parent / ("job-" + os.urandom(16).hex())
            private(probe)
            shutil.copyfile(job / helper_name, probe / helper_name)
            if not windows:
                (probe / helper_name).chmod(0o700)
            request = copy.deepcopy(original_request)
            probe_env = environment.copy()
            if change == "creation time": request["parent"]["started"] = "0"
            if change == "parent image": request["parent"]["image"] = str(probe / helper_name)
            if change == "image hash": request["old_sha256"] = "0" * 64
            if change == "protocol": request["protocol"] = 99
            if change == "trust": probe_env["FIXER_TEST_APP_TRUST"] = str(other_public)
            if change == "request trust override": request["key"] = str(other_public)
            (probe / "request.json").write_text(json.dumps(request), encoding="utf-8")
            result = subprocess.run([str(probe / helper_name), "--internal-app-update", str(probe / "request.json")],
                                    env=probe_env, capture_output=True, timeout=25)
            check("native helper rejects wrong " + change,
                  result.returncode == 4 and wait_status(probe, {"failed"})["exit_code"] == 4 and target.read_bytes() == source)
    finally:
        release(parent)
    result = wait_status(job, {"installed", "failed"})
    check("native helper installs signed inert payload after parent exit",
          result["state"] == "installed" and target.read_bytes() == bytes(binary))
    before = (job / "status.json").read_bytes()
    # The job may have reported its result just before the process exits.
    # Replays are rejected both by the live lock and by the terminal status.
    replay = subprocess.run([str(job / helper_name), "--internal-app-update", str(job / "request.json")],
                            env=environment, capture_output=True, timeout=25)
    check("native helper rejects completed request replay",
          replay.returncode != 0 and (job / "status.json").read_bytes() == before and target.read_bytes() == bytes(binary))
    if program:
        status = subprocess.run([str(program), "--app-update-status", str(job), "--json"],
                                env=environment, capture_output=True, timeout=15)
        check("shipped CLI reads native helper result without writes",
              status.returncode == 0 and json.loads(status.stdout)["state"] == "installed" and
              (job / "status.json").read_bytes() == before)

    config = root / "restore native fixture.json"
    config.write_text(json.dumps({"restore": True, "target": str(target)}), encoding="utf-8")
    restored = subprocess.run([str(job / helper_name), str(config)], env=environment,
                              capture_output=True, timeout=25)
    if restored.returncode:
        raise RuntimeError(f"Could not schedule native recovery: {restored.stderr!r}")
    restore_job = Path(json.loads(restored.stdout)["job"])
    check("persistent helper restores app after inert target cannot run",
          wait_status(restore_job, {"restored", "failed"})["state"] == "restored" and target.read_bytes() == source)

    if program:
        config.write_text(json.dumps({"directory": str(handoff)}), encoding="utf-8")
        installed = subprocess.run([str(target), str(config)], env=environment,
                                   capture_output=True, timeout=25)
        if installed.returncode:
            raise RuntimeError(f"Could not prepare CLI recovery: {installed.stderr!r}")
        update_job = Path(json.loads(installed.stdout)["job"])
        if wait_status(update_job, {"installed", "failed"})["state"] != "installed":
            raise RuntimeError("Could not install synthetic payload for CLI recovery")
        restored = subprocess.run([str(program), "--restore-app", str(target)], env=environment,
                                  capture_output=True, timeout=25)
        if restored.returncode:
            raise RuntimeError(f"Shipped CLI could not schedule recovery: {restored.stderr!r}")
        lines = restored.stdout.decode("utf-8").splitlines()
        restore_job = Path(next(line[5:] for line in lines if line.startswith("Job: ")))
        check("shipped CLI schedules native app recovery",
              wait_status(restore_job, {"restored", "failed"})["state"] == "restored" and target.read_bytes() == source)

    for fault in ("abort", "changed staging"):
        parent, target, job = launch(fault)
        payload = handoff / "bin" / name
        try:
            if fault == "abort":
                (job / "abort.json").write_text('{"abort":true}', encoding="ascii")
            else:
                payload.write_bytes(bytes(binary) + b"tampered")
        finally:
            release(parent)
        try:
            status = wait_status(job, {"failed", "installed"})
            check("native helper preserves app after " + fault,
                  status["state"] == "failed" and status["exit_code"] == (130 if fault == "abort" else 4) and
                  target.read_bytes() == source and not (target.parent / ".helium-app-update").exists())
            if program:
                reported = subprocess.run([str(program), "--app-update-status", str(job), "--json"],
                                          env=environment, capture_output=True, timeout=15)
                check("shipped CLI reports helper failure after " + fault,
                      reported.returncode == status["exit_code"] and json.loads(reported.stdout)["state"] == "failed")
        finally:
            payload.write_bytes(binary)
    return passed
