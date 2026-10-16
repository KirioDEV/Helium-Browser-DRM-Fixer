"""Test production DNS deadlines in an isolated Linux container.

Requires loopback DNS (--dns 127.0.0.1), no external network (--network none),
and permission to bind UDP port 53. This script changes no resolver settings.
"""

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


class Blackhole:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 53))
        self.socket.settimeout(0.1)
        self.condition = threading.Condition()
        self.packets = 0
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stopping.is_set():
            try:
                self.socket.recvfrom(4096)  # Intentionally never answer.
            except socket.timeout:
                continue
            except OSError:
                return
            with self.condition:
                self.packets += 1
                self.condition.notify_all()

    def close(self):
        self.stopping.set()
        self.socket.close()
        self.worker.join(timeout=2)


def main():
    if sys.platform != "linux" or len(sys.argv) < 2:
        raise RuntimeError("Pass production executable paths inside a Linux container")
    servers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
               if line.split() and line.split()[0] == "nameserver"]
    if servers != ["127.0.0.1"]:
        raise RuntimeError("Use an isolated container with --dns 127.0.0.1")
    blackhole = Blackhole()
    try:
        for argument in sys.argv[1:]:
            executable = Path(argument).resolve()
            for cancel in (False, True):
                with tempfile.TemporaryDirectory(prefix="helium-dns-blackhole-") as temporary:
                    root = Path(temporary)
                    profile = root / "profile"
                    profile.mkdir()
                    environment = os.environ.copy()
                    environment.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "config"),
                                       XDG_CACHE_HOME=str(root / "cache"),
                                       RES_OPTIONS="timeout:30 attempts:1")
                    with blackhole.condition:
                        before = blackhole.packets
                    start = time.monotonic()
                    process = subprocess.Popen(
                        [str(executable), "--helium-path", str(profile / "WidevineCdm")],
                        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True)
                    try:
                        with blackhole.condition:
                            observed = blackhole.condition.wait_for(
                                lambda: blackhole.packets > before, timeout=5)
                        if not observed:
                            raise RuntimeError("Production resolver did not send a DNS query")
                        if cancel:
                            process.send_signal(signal.SIGINT)
                        stdout, stderr = process.communicate(timeout=15)
                        elapsed = time.monotonic() - start
                        code, message = (130, "Operation cancelled") if cancel else (1, "DNS lookup timeout")
                        if process.returncode != code or message not in stderr:
                            raise RuntimeError(f"Unexpected DNS failure: {process.returncode}: {stdout}{stderr}")
                        if elapsed > (2 if cancel else 14):
                            raise RuntimeError(f"Resolver or shutdown blocked for {elapsed:.2f} seconds")
                        if not cancel and elapsed < 9:
                            raise RuntimeError("DNS timeout occurred before the production 10-second budget")
                        if any(profile.iterdir()) or (root / "cache").exists():
                            raise RuntimeError("DNS failure created installation or cache files")
                        print(f"{executable.parent.name}: actual system DNS "
                              f"{'cancellation' if cancel else 'deadline'} passed "
                              f"({elapsed:.2f} seconds)", flush=True)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()
    finally:
        blackhole.close()


if __name__ == "__main__":
    main()
