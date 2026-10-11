"""Exercise real process death between filesystem rename and journal update."""
from pathlib import Path
import subprocess
import tempfile
import sys

executable = Path(sys.argv[1]).resolve()
for phase in ("prepared", "old_renamed", "old_moved", "new_renamed", "new_moved"):
    with tempfile.TemporaryDirectory(prefix="helium-fixer-crash-") as directory:
        target = str(Path(directory) / "WidevineCdm")
        result = subprocess.run([str(executable), "--crash", target, phase], check=False)
        if result.returncode != 77:
            raise RuntimeError(f"Crash injection failed at {phase}: {result.returncode}")
        subprocess.run([str(executable), "--recover", target], check=True)
print("Five real crash/recovery scenarios passed")
