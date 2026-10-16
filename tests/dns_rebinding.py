"""Exercise real system DNS and HTTPS pinning in a disposable Linux container.

Requires --network none --dns 127.0.0.1 --cap-add NET_ADMIN. Public fixture
addresses are assigned only to this container's loopback interface. TLS uses
the existing isolated test executable and a private CA file, never system trust.
"""

import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from network_integration import Server


PUBLIC = "8.8.8.8"
SECOND = "8.8.4.4"
PRIVATE = "127.0.0.1"
HOST = "dl.google.com"


def add_fixture_addresses():
    import fcntl

    servers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
               if line.split() and line.split()[0] == "nameserver"]
    if (not Path("/.dockerenv").exists() or
            {name for _index, name in socket.if_nameindex()} != {"lo"} or
            servers != [PRIVATE]):
        raise RuntimeError("Use a disposable Docker container with --network none --dns 127.0.0.1")
    # Linux x86_64 ifreq: interface name (16), sockaddr (16), union padding (8).
    # https://man7.org/linux/man-pages/man7/netdevice.7.html
    # Only named aliases of lo are changed; the primary 127.0.0.1 is preserved.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for index, address in enumerate((PUBLIC, SECOND)):
            label = f"lo:drm{index}".encode("ascii")
            for operation, value in ((0x8916, address), (0x891c, "255.255.255.255")):
                request = struct.pack("16sH2s4s8s8x", label, socket.AF_INET,
                                      b"\0\0", socket.inet_aton(value), b"\0" * 8)
                fcntl.ioctl(control, operation, request)


class DnsServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((PRIVATE, 53))
        self.socket.settimeout(0.1)
        self.lock = threading.Lock()
        self.mode = "rebind"
        self.queries = []
        self.errors = []
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def reset(self, mode):
        with self.lock:
            self.mode = mode
            self.queries.clear()
            self.errors.clear()

    def answer(self, packet):
        if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
            raise ValueError("Expected one DNS question")
        offset, labels = 12, []
        while True:
            size = packet[offset]
            offset += 1
            if size == 0:
                break
            if size > 63 or offset + size > len(packet) or offset > 267:
                raise ValueError("Invalid DNS question name")
            labels.append(packet[offset:offset + size].decode("ascii"))
            offset += size
        kind, category = struct.unpack_from("!HH", packet, offset)
        end = offset + 4
        name = ".".join(labels).lower()
        if name != HOST or category != 1:
            raise ValueError(f"Unexpected DNS question: {name}, {kind}, {category}")
        with self.lock:
            self.queries.append(kind)
            a_count = self.queries.count(1)
            mode = self.mode
        addresses = []
        if mode != "nxdomain":
            if kind == 1:
                if mode == "private":
                    addresses = [PRIVATE]
                elif mode == "mixed-v4":
                    addresses = [PUBLIC, PRIVATE]
                elif a_count == 1:
                    addresses = [PUBLIC]
                else:
                    addresses = [SECOND if mode == "public-shift" else PRIVATE]
            elif kind == 28 and mode == "mixed-v6":
                addresses = ["::1"]
        records = []
        for address in addresses:
            data = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, address)
            # Name pointer to the original question, IN class, TTL zero.
            records.append(b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(data)) + data)
        flags = 0x8183 if mode == "nxdomain" else 0x8180
        return (packet[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) +
                packet[12:end] + b"".join(records))

    def run(self):
        while not self.stopping.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.socket.sendto(self.answer(packet), peer)
            except (ValueError, IndexError, UnicodeError, struct.error, OSError) as error:
                with self.lock:
                    self.errors.append(str(error))

    def witness_rebind(self):
        # After the client used its pin, prove over UDP that the next answer is
        # actually private. The client must never have made this second lookup.
        question = b"".join(bytes([len(label)]) + label.encode("ascii")
                            for label in HOST.split(".")) + b"\0\0\x01\0\x01"
        packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as witness:
            witness.settimeout(2)
            witness.sendto(packet, (PRIVATE, 53))
            answer, _peer = witness.recvfrom(4096)
        if answer[:2] != packet[:2] or answer[-4:] != socket.inet_aton(PRIVATE):
            raise RuntimeError("DNS fixture did not actually rebind to loopback")

    def close(self):
        self.stopping.set()
        self.socket.close()
        self.worker.join(timeout=2)


def main():
    if sys.platform != "linux" or len(sys.argv) < 2:
        raise RuntimeError("Pass isolated network probe executables in a Linux container")
    add_fixture_addresses()
    dns = DnsServer()
    try:
        with tempfile.TemporaryDirectory(prefix="helium-dns-rebinding-") as temporary:
            root = Path(temporary)

            def openssl(*arguments):
                subprocess.run(["openssl", *arguments], cwd=root, check=True,
                               capture_output=True, timeout=20)

            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=Ephemeral rebinding test CA", "-keyout", "ca.key",
                    "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE")
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                    f"/CN={HOST}", "-keyout", "leaf.key", "-out", "leaf.csr")
            (root / "leaf.ext").write_text(
                f"basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{HOST}\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n", encoding="ascii")
            openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey",
                    "ca.key", "-CAcreateserial", "-days", "1", "-extfile", "leaf.ext",
                    "-out", "leaf.pem")
            cases = (("pin survives rebinding", "rebind", "/ok", 0, 1, ["/ok"], []),
                     ("redirect rejects rebinding", "rebind", "/redirect", 4, 2, ["/redirect"], []),
                     ("redirect accepts new public IP", "public-shift", "/redirect", 0, 2,
                      ["/redirect"], ["/ok"]),
                     ("mixed IPv4 DNS answers", "mixed-v4", "/ok", 4, 1, [], []),
                     ("mixed IPv4/IPv6 DNS answers", "mixed-v6", "/ok", 4, 1, [], []),
                     ("private DNS answer", "private", "/ok", 4, 1, [], []),
                     ("NXDOMAIN", "nxdomain", "/ok", 1, 1, [], []))
            for argument in sys.argv[1:]:
                probe = Path(argument).resolve()
                for name, mode, path, code, lookups, first_paths, second_paths in cases:
                    servers = []
                    try:
                        first = Server(root / "leaf.pem", root / "leaf.key", PUBLIC)
                        servers.append(first)
                        second = Server(root / "leaf.pem", root / "leaf.key", SECOND, first.server_port)
                        servers.append(second)
                        attacker = Server(root / "leaf.pem", root / "leaf.key", PRIVATE, first.server_port)
                        servers.append(attacker)
                        dns.reset(mode)
                        config = {"port": first.server_port, "url": f"https://{HOST}{path}",
                                  "ca_file": str(root / "ca.pem"), "system_dns": True}
                        request = root / "request.json"
                        request.write_text(json.dumps(config), encoding="utf-8")
                        result = subprocess.run([str(probe), str(request)], capture_output=True,
                                                text=True, timeout=10)
                        if not result.stdout.strip():
                            raise RuntimeError(f"{name}: exit {result.returncode}: {result.stderr}")
                        response = json.loads(result.stdout)
                        if result.returncode != code or response["ok"] != (code == 0):
                            raise RuntimeError(f"{name}: unexpected response: {response}")
                        if code == 0 and response["data"] != b"fixture".hex():
                            raise RuntimeError(f"{name}: wrong HTTP body")
                        if first.requests != first_paths or second.requests != second_paths:
                            raise RuntimeError(f"{name}: incorrect public server requests")
                        if attacker.requests or attacker.server_names:
                            raise RuntimeError(f"{name}: client contacted the private rebinding target")
                        for server in servers[:2]:
                            if any(value != HOST for value in server.server_names):
                                raise RuntimeError(f"{name}: TLS identity changed to the pinned IP")
                            if any(value != f"{HOST}:{first.server_port}" for value in server.hosts):
                                raise RuntimeError(f"{name}: HTTP Host changed to the pinned IP")
                        with dns.lock:
                            if dns.errors or dns.queries.count(1) != lookups:
                                raise RuntimeError(f"{name}: unexpected DNS traffic: "
                                                   f"{dns.queries}, {dns.errors}")
                        if name == "pin survives rebinding":
                            dns.witness_rebind()
                        print(f"{probe.parent.name}: {name}: passed", flush=True)
                    finally:
                        for server in reversed(servers):
                            server.close()
    finally:
        dns.close()


if __name__ == "__main__":
    main()
