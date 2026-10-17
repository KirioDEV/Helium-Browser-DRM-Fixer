"""Offline app replacement using signed synthetic files; never executes them."""

import hashlib
import json
import os
import subprocess
import sys


def exercise_app_transactions(helper, root, handoff, public, other_public, binary):
    passed = 0
    windows = sys.platform == "win32"
    filename = "helium_drm_fixer.exe" if windows else "helium_drm_fixer"
    old = bytes(binary) + b"previous synthetic application"
    old_hash = hashlib.sha256(old).hexdigest()
    new_hash = hashlib.sha256(binary).hexdigest()
    config_file = root / "app transaction config.json"

    def fixture(name):
        parent = root / ("app transaction " + name)
        subprocess.run([str(helper), "--create-private-app-staging", str(parent)],
                       capture_output=True, timeout=15, check=True)
        target = parent / filename
        target.write_bytes(old)
        if not windows:
            target.chmod(0o700)
        return target

    def snapshot(parent):
        return {p.relative_to(parent).as_posix(): p.read_bytes()
                for p in parent.rglob("*") if p.is_file()}

    def execute(name, target, expected=0, **options):
        nonlocal passed
        config_file.write_text(json.dumps({
            "target": str(target), "directory": str(handoff),
            "key": str(public), "old_sha256": old_hash, **options,
        }), encoding="utf-8")
        result = subprocess.run([str(helper), "--app-transaction-fixture", str(config_file)],
                                capture_output=True, timeout=15)
        if result.returncode != expected:
            raise RuntimeError(f"{name}: expected {expected}, got {result.returncode}: {result.stderr!r}")
        passed += 1
        print(f"{name}: passed", flush=True)

    def journal(target):
        state = target.parent / ".helium-app-update"
        value = json.loads((state / "journal.json").read_bytes())
        return state, value

    def restored(target):
        if target.read_bytes() != old or journal(target)[1]["phase"] != "restored":
            raise RuntimeError("App rollback did not restore the previous executable")
        if not windows and target.stat().st_mode & 0o777 != 0o700:
            raise RuntimeError("Rollback lost the previous executable mode")

    target = fixture("successful update")
    execute("app executable replacement", target)
    state, value = journal(target)
    if target.read_bytes() != bytes(binary) or value["phase"] != "committed":
        raise RuntimeError("App transaction did not commit the signed executable")
    if (state / ("backup-" + value["id"])).read_bytes() != old:
        raise RuntimeError("Committed app update did not retain its backup")
    if value["new_sha256"] != new_hash or value["old_sha256"] != old_hash:
        raise RuntimeError("App journal hashes do not bind both executables")
    if not windows and target.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError("Updated executable lost its private executable mode")
    before = snapshot(target.parent)
    execute("stale app helper cannot replace updated target", target, 4)
    if snapshot(target.parent) != before:
        raise RuntimeError("Stale app helper modified transaction files")
    # Model a later attempt that archived this committed journal but failed
    # before publishing its own journal. Explicit rollback must not poison the
    # history check for the next update.
    (state / ("history-" + value["id"] + ".json")).write_text(json.dumps(value), encoding="utf-8")
    execute("explicit rollback of committed app update", target, operation="restore", cancelled=True)
    restored(target)
    before = snapshot(target.parent)
    execute("app rollback is idempotent", target, operation="restore")
    if snapshot(target.parent) != before:
        raise RuntimeError("Repeated app recovery changed files")
    execute("new app transaction after rollback", target)
    if not list(state.glob("history-*.json")):
        raise RuntimeError("App transaction discarded previous journal")

    target = fixture("exclusive lock")
    execute("app transaction excludes concurrent recovery", target,
            phase="prepared", fault="lock")

    if windows:
        target = fixture("locked executable")
        execute("Windows locked app executable blocks replacement", target, 1, locked_target=True)
        restored(target)
        execute("Windows replacement after app lock released", target)

    phases = ("staging", "prepared", "old_renamed", "old_moved", "new_renamed", "new_moved")
    for fault, code in (("fail", 1), ("cancel", 130)):
        for phase in phases:
            target = fixture(f"{fault} {phase}")
            execute(f"app {fault} at {phase}", target, code, phase=phase, fault=fault)
            if target.read_bytes() != old:
                raise RuntimeError("Failed app transaction changed the installed executable")
            if phase != "staging":
                restored(target)
            # A failed attempt before its journal must not prevent a retry or
            # cause recovery to act on the preceding committed transaction.
            execute(f"app retry after {fault} at {phase}", target)

    for phase in phases[1:]:
        target = fixture("crash " + phase)
        execute(f"app process crash at {phase}", target, 77, phase=phase, fault="crash")
        if phase in ("old_renamed", "old_moved") and target.exists():
            raise RuntimeError("Crash probe did not exercise a missing executable")
        before = snapshot(target.parent)
        execute(f"pending app transaction blocks another install at {phase}", target,
                1 if not target.exists() else (5 if phase == "prepared" else 4))
        if snapshot(target.parent) != before:
            raise RuntimeError("Pending app transaction was overwritten")
        execute(f"fresh process recovers app crash at {phase}", target, operation="restore")
        restored(target)

    for phase in ("restore_validated", "restore_current_moved", "restore_backup_moved"):
        target = fixture("restore crash " + phase)
        execute("prepare app recovery crash " + phase, target)
        execute("app recovery process crash " + phase, target, 77,
                operation="restore", phase=phase, fault="crash")
        execute("resume interrupted app recovery " + phase, target, operation="restore", cancelled=True)
        restored(target)

    for name, options, code in (
        ("wrong observed hash", {"old_sha256": "0" * 64}, 4),
        ("invalid observed hash", {"old_sha256": "../outside"}, 4),
        ("foreign signature", {"key": str(other_public)}, 4),
        ("compiled signature root", {"compiled_trust": True}, 4),
        ("wrong expected version", {"version": "1.2.4"}, 4),
        ("early cancellation", {"cancelled": True}, 130),
    ):
        target = fixture(name)
        before = snapshot(target.parent)
        execute("app rejects " + name, target, code, **options)
        if snapshot(target.parent) != before:
            raise RuntimeError("Rejected app request modified files")

    target = fixture("hardlink")
    alias = target.parent / "alias"
    os.link(target, alias)
    before = snapshot(target.parent)
    execute("app rejects hardlinked target", target, 4)
    if snapshot(target.parent) != before:
        raise RuntimeError("Hardlinked app target was modified")

    target = fixture("unknown owner")
    state = target.parent / ".helium-app-update"
    subprocess.run([str(helper), "--create-private-app-staging", str(state)],
                   capture_output=True, timeout=15, check=True)
    (state / "owner.json").write_text('{}', encoding="utf-8")
    before = snapshot(target.parent)
    execute("app install preserves unrelated state directory", target, 4)
    execute("app recovery preserves unrelated state directory", target, 4, operation="restore")
    if snapshot(target.parent) != before:
        raise RuntimeError("Unrelated app state directory was changed")

    if not windows:
        target = fixture("symlink")
        original = target.parent / "original"
        target.rename(original)
        target.symlink_to(original)
        before = snapshot(target.parent)
        execute("app rejects symlinked target", target, 4)
        if snapshot(target.parent) != before or not target.is_symlink():
            raise RuntimeError("Symlinked app target was changed")

    target = fixture("noncanonical target")
    target.rename(target.parent / "unrelated.exe")
    before = snapshot(target.parent)
    execute("app rejects unexpected target filename", target.parent / "unrelated.exe", 4)
    if snapshot(target.parent) != before:
        raise RuntimeError("Unexpected app target was changed")

    for damaged in ("backup", "target", "journal"):
        target = fixture("modified " + damaged)
        execute("prepare app tampering " + damaged, target)
        state, value = journal(target)
        if damaged == "backup":
            (state / ("backup-" + value["id"])).write_bytes(b"unrelated backup")
        elif damaged == "target":
            target.write_bytes(b"unrelated user file")
        else:
            value["id"] = "../../outside"
            (state / "journal.json").write_text(json.dumps(value), encoding="utf-8")
        before = snapshot(target.parent)
        execute("app recovery preserves modified " + damaged, target, 5, operation="restore")
        if snapshot(target.parent) != before:
            raise RuntimeError("App recovery changed unrecognized files")

    target = fixture("changed during install")
    execute("app preserves concurrent target change", target, 5,
            phase="new_moved", fault="tamper")
    state, value = journal(target)
    if target.read_bytes() != b"unrelated user file" or (state / ("backup-" + value["id"])).read_bytes() != old:
        raise RuntimeError("Failed rollback lost the backup or an unrelated target")
    target.unlink()  # Explicit test repair of this synthetic target only.
    execute("app recovery after explicit removal of unknown target", target, operation="restore")
    restored(target)
    return passed
