"""Exercise native HTTPS against ephemeral loopback fixtures, without system trust changes."""

import argparse
import hashlib
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, certificate, key):
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=5)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def handle(self):
        try:
            super().handle()
        except (OSError, ssl.SSLError):
            pass  # A client may reject TLS before sending an HTTP request.

    def do_POST(self):
        self.server.requests.append(self.path)
        self.close_connection = True
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(302)
        self.send_header("Location", "/forbidden")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.server.requests.append(self.path)
        self.close_connection = True
        try:
            if self.path in ("/stall", "/cancel"):
                time.sleep(3)
                return
            if self.path.startswith("/budget/"):
                step = int(self.path.rsplit("/", 1)[1])
                time.sleep(0.4)
                if step < 3:
                    self.send_response(302)
                    self.send_header("Location", f"/budget/{step + 1}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            redirect = {
                "/redirect": "/ok",
                "/foreign": "https://evil.example/forbidden",
                "/downgrade": "http://dl.google.com/forbidden",
                "/loopback": "https://127.0.0.1/forbidden",
            }.get(self.path)
            if redirect:
                self.send_response(302)
                self.send_header("Location", redirect)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            if self.path == "/declared-oversized":
                self.send_header("Content-Length", "65536")
            elif self.path == "/truncated":
                self.send_header("Content-Length", "100")
            elif self.path not in ("/unknown", "/oversized", "/stream", "/body-stall", "/chunked"):
                self.send_header("Content-Length", "7")
            if self.path == "/chunked":
                self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.path == "/oversized":
                self.wfile.write(b"x" * 65536)
            elif self.path == "/chunked":
                self.wfile.write(b"3\r\nfix\r\n4\r\nture\r\n0\r\n\r\n")
            elif self.path == "/body-stall":
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(3)
            elif self.path == "/stream":
                for _ in range(30):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.1)
            else:
                self.wfile.write(b"fixture")
            self.wfile.flush()
        except (OSError, ssl.SSLError):
            pass  # Deliberate client rejection, timeout or cancellation.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--production", required=True, type=Path)
    parser.add_argument("--openssl", required=True, type=Path)
    args = parser.parse_args()
    args.probe = args.probe.resolve()
    args.production = args.production.resolve()
    args.openssl = args.openssl.resolve()
    # The fixture-only diagnostics must never be present in the shipped executable.
    marker = b"Invalid network fixture settings"
    if marker in args.production.read_bytes():
        raise RuntimeError("Network test configuration leaked into production executable")
    if marker not in args.probe.read_bytes():
        raise RuntimeError("Fixture isolation marker missing from test executable")
    production = subprocess.run([str(args.production), "--network-fixture"],
                                capture_output=True, text=True, timeout=10)
    if production.returncode != 2:
        raise RuntimeError("Production executable accepted a fixture-only option")

    with tempfile.TemporaryDirectory(prefix="helium-fixer-tls-") as temporary:
        root = Path(temporary)

        def openssl(*arguments):
            subprocess.run([str(args.openssl), *arguments], cwd=root, check=True,
                           capture_output=True, timeout=20)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=Helium ephemeral test CA", "-keyout", "ca.key",
                "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                "/CN=dl.google.com", "-keyout", "leaf.key", "-out", "leaf.csr")
        for name, san, days in (("valid", "DNS:dl.google.com,DNS:update.googleapis.com,IP:127.0.0.1", "1"),
                                ("wrong-host", "DNS:wrong.example", "1"),
                                ("expired", "DNS:dl.google.com,IP:127.0.0.1", "0")):
            (root / "leaf.ext").write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n", encoding="ascii")
            openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey",
                    "ca.key", "-CAcreateserial", "-days", days, "-extfile", "leaf.ext",
                    "-out", f"{name}.pem")
            (root / f"{name}-chain.pem").write_bytes(
                (root / f"{name}.pem").read_bytes() + (root / "ca.pem").read_bytes())

        passed = 0

        def exercise(name, path, expected_code=0, *, certificate="valid", trust=True,
                     expected_paths=None, maximum_ms=4000, **options):
            nonlocal passed
            server = Server(root / f"{certificate}-chain.pem", root / "leaf.key")
            try:
                peer = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                    (root / f"{certificate}.pem").read_text(encoding="ascii"))).hexdigest()
                config = {"port": server.server_port, "url": f"https://dl.google.com{path}",
                          "ca_file": str(root / "ca.pem") if trust else "",
                          "peer_sha256": peer if trust else "", **options}
                request_file = root / "request-ä-中.json"
                request_file.write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([str(args.probe), str(request_file)],
                                        capture_output=True, text=True, timeout=10)
                if not result.stdout.strip():
                    raise RuntimeError(f"{name}: probe failed without JSON: {result.stderr}")
                response = json.loads(result.stdout)
                if result.returncode != expected_code or response["ok"] != (expected_code == 0):
                    raise RuntimeError(f"{name}: unexpected result {result.returncode}: {response}")
                if expected_code == 0 and response["data"] != b"fixture".hex():
                    raise RuntimeError(f"{name}: wrong body: {response}")
                if response["elapsed_ms"] > maximum_ms:
                    raise RuntimeError(f"{name}: response exceeded timing bound: {response}")
                if expected_paths is not None and server.requests != expected_paths:
                    raise RuntimeError(f"{name}: unexpected requests: {server.requests}")
                passed += 1
                print(f"{name}: passed ({response['elapsed_ms']} ms)", flush=True)
            finally:
                server.close()

        exercise("trusted fixture", "/ok", expected_paths=["/ok"])
        if sys.platform == "win32":
            exercise("fixture peer pin mismatch", "/ok", 4, peer_sha256="0" * 64)
        exercise("untrusted CA", "/ok", 1, trust=False, expected_paths=[])
        exercise("hostname mismatch", "/ok", 1, certificate="wrong-host", expected_paths=[])
        exercise("expired certificate", "/ok", 1, certificate="expired", expected_paths=[])
        exercise("unknown-length response", "/unknown", expected_paths=["/unknown"])
        exercise("chunked response", "/chunked", expected_paths=["/chunked"])
        exercise("oversized unknown-length response", "/oversized", 4, limit=1024)
        exercise("oversized declared response", "/declared-oversized", 4, limit=1024)
        exercise("truncated response", "/truncated", 1)
        exercise("allowed relative redirect", "/redirect", expected_paths=["/redirect", "/ok"])
        for path in ("/foreign", "/downgrade", "/loopback"):
            exercise(f"rejected redirect {path}", path, 4, expected_paths=[path])
        exercise("POST update redirect rejected", "/service/update2/json", 4,
                 url="https://update.googleapis.com/service/update2/json", update=True,
                 body='{"fixture":true}', expected_paths=["/service/update2/json"])
        exercise("response-header timeout", "/stall", 1, total_ms=350, maximum_ms=1500)
        exercise("body idle timeout", "/body-stall", 1)
        exercise("total deadline while streaming", "/stream", 1, total_ms=350, maximum_ms=1500)
        exercise("total deadline across redirects", "/budget/0", 1, total_ms=950,
                 idle_ms=3000)
        exercise("cancellation while stalled", "/cancel", 130, cancel_after_ms=100)
        exercise("cancellation while streaming", "/stream", 130, cancel_after_ms=150)
        print(f"{passed} native HTTPS scenarios and production isolation passed")


if __name__ == "__main__":
    main()
