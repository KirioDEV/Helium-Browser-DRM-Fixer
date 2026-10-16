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

    def __init__(self, certificate, key, host="127.0.0.1", port=0):
        super().__init__((host, port), Handler)
        self.requests = []
        self.hosts = []
        self.server_names = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        context.set_servername_callback(
            lambda _socket, name, _context: self.server_names.append(name))
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
        self.server.hosts.append(self.headers.get("Host"))
        self.close_connection = True
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(302)
        self.send_header("Location", "/forbidden")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.server.requests.append(self.path)
        self.server.hosts.append(self.headers.get("Host"))
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
            if self.path == "/repos/KirioDEV/Helium-Browser-DRM-Fixer/releases/latest":
                status = getattr(self.server, "release_status", 200)
                if status != 200:
                    self.send_response(status)
                    self.send_header("Location", "https://evil.example/forbidden")
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
        openssl("req", "-new", "-key", "leaf.key", "-subj", "/CN=127.0.0.1",
                "-out", "ip-only.csr")
        for name, san, days in (("valid", "DNS:dl.google.com,DNS:update.googleapis.com,DNS:api.github.com,IP:127.0.0.1", "1"),
                                ("wrong-host", "DNS:wrong.example", "1"),
                                ("expired", "DNS:dl.google.com,IP:127.0.0.1", "0"),
                                ("ip-only", "IP:127.0.0.1", "1")):
            (root / "leaf.ext").write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n", encoding="ascii")
            openssl("x509", "-req", "-in", "ip-only.csr" if name == "ip-only" else "leaf.csr", "-CA", "ca.pem", "-CAkey",
                    "ca.key", "-CAcreateserial", "-days", days, "-extfile", "leaf.ext",
                    "-out", f"{name}.pem")
            (root / f"{name}-chain.pem").write_bytes(
                (root / f"{name}.pem").read_bytes() + (root / "ca.pem").read_bytes())

        passed = 0

        def exercise(name, path, expected_code=0, *, certificate="valid", trust=True,
                     expected_paths=None, maximum_ms=4000, release_status=200, **options):
            nonlocal passed
            server = Server(root / f"{certificate}-chain.pem", root / "leaf.key")
            server.release_status = release_status
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
                    raise RuntimeError(f"{name}: probe failed without JSON "
                                       f"(exit {result.returncode}): {result.stderr}")
                response = json.loads(result.stdout)
                if result.returncode != expected_code or response["ok"] != (expected_code == 0):
                    raise RuntimeError(f"{name}: unexpected result {result.returncode}: {response}")
                if expected_code == 0 and response["data"] != b"fixture".hex():
                    raise RuntimeError(f"{name}: wrong body: {response}")
                if response["elapsed_ms"] > maximum_ms:
                    raise RuntimeError(f"{name}: response exceeded timing bound: {response}")
                if expected_paths is not None and server.requests != expected_paths:
                    raise RuntimeError(f"{name}: unexpected requests: {server.requests}")
                if expected_paths:
                    host = ("api.github.com" if config.get("app_release") else
                            "update.googleapis.com" if config.get("update") else "dl.google.com")
                    if any(value.split(":", 1)[0] != host for value in server.hosts):
                        raise RuntimeError(f"{name}: IP pinning changed Host: {server.hosts}")
                    if not server.server_names or any(value != host for value in server.server_names):
                        raise RuntimeError(f"{name}: IP pinning changed TLS SNI: {server.server_names}")
                passed += 1
                print(f"{name}: passed ({response['elapsed_ms']} ms)", flush=True)
            finally:
                server.close()

        exercise("trusted fixture", "/ok", expected_paths=["/ok"])
        app_path = "/repos/KirioDEV/Helium-Browser-DRM-Fixer/releases/latest"
        app_options = {"app_release": True, "url": f"https://api.github.com{app_path}"}
        exercise("app release HTTPS and pinned Host/SNI", app_path,
                 expected_paths=[app_path], **app_options)
        exercise("app release cannot redirect", app_path, 4, release_status=302,
                 expected_paths=[app_path], **app_options)
        exercise("app release rate limit", app_path, 1, release_status=403,
                 expected_paths=[app_path], **app_options)
        exercise("app release CA validation", app_path, 1, trust=False,
                 expected_paths=[], **app_options)
        exercise("app release hostname validation", app_path, 1,
                 certificate="wrong-host", expected_paths=[], **app_options)
        exercise("app release rejects private DNS", app_path, 4,
                 dns_answers=[["127.0.0.1"]], expected_paths=[], **app_options)
        exercise("CDM policy still rejects GitHub", app_path, 4,
                 url=f"https://api.github.com{app_path}", expected_paths=[])
        if sys.platform == "win32":
            exercise("fixture peer pin mismatch", "/ok", 4, peer_sha256="0" * 64)
        exercise("untrusted CA", "/ok", 1, trust=False, expected_paths=[])
        exercise("hostname mismatch", "/ok", 1, certificate="wrong-host", expected_paths=[])
        exercise("pinned IP is not the TLS identity", "/ok", 1,
                 certificate="ip-only", expected_paths=[])
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
        exercise("DNS failure", "/ok", 1, dns_failure=True, expected_paths=[])
        exercise("system DNS cannot mix injected answers", "/ok", 4,
                 system_dns=True, dns_answers=[["8.8.8.8"]], expected_paths=[])
        exercise("DNS lookup deadline", "/ok", 1, dns_ms=150,
                 dns_delay_ms=1800, maximum_ms=1000, expected_paths=[])
        exercise("total deadline includes DNS", "/ok", 1, total_ms=150,
                 dns_ms=3000, dns_delay_ms=1800, maximum_ms=1000, expected_paths=[])
        exercise("cancellation during DNS", "/ok", 130, dns_delay_ms=1800,
                 cancel_after_ms=100, maximum_ms=1000, expected_paths=[])
        exercise("slow DNS success", "/ok", dns_delay_ms=100,
                 expected_paths=["/ok"])
        exercise("DNS consumes redirect budget", "/redirect", 1,
                 dns_delay_ms=200, total_ms=350, maximum_ms=1200,
                 expected_paths=["/redirect"])
        exercise("abandoned DNS worker lifetime and reuse", "/ok",
                 dns_lifecycle=True, maximum_ms=2500, expected_paths=["/ok"])
        exercise("empty DNS answer", "/ok", 1, dns_answers=[[]], expected_paths=[])
        exercise("public IPv4 DNS answer", "/ok", dns_answers=[["8.8.8.8"]],
                 expected_paths=["/ok"])
        exercise("public IPv6 DNS answer", "/ok", dns_answers=[["2001:4860:4860::8888"]],
                 expected_paths=["/ok"])
        exercise("mixed public DNS answer", "/ok",
                 dns_answers=[["8.8.8.8", "2001:4860:4860::8888"]], expected_paths=["/ok"])
        for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1",
                        "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1",
                        "2001:db8::1", "2001::1", "2001:2::1", "2002:7f00:1::1",
                        "3fff::1", "64:ff9b::7f00:1", "not-an-ip"):
            exercise(f"reject mixed DNS answer {address}", "/ok", 4,
                     dns_answers=[["8.8.8.8", address]], expected_paths=[])
        exercise("reject excessive DNS answers", "/ok", 4,
                 dns_answers=[["8.8.8.8"] * 65], expected_paths=[])
        exercise("recheck DNS on redirect", "/redirect", 4,
                 dns_answers=[["8.8.8.8"], ["127.0.0.1"]], expected_paths=["/redirect"])
        exercise("recheck DNS on redirect with mixed answer", "/redirect", 4,
                 dns_answers=[["8.8.8.8"], ["8.8.8.8", "::1"]], expected_paths=["/redirect"])
        # Exercise process teardown repeatedly without TLS callbacks, isolating
        # the resolver thread's lifetime from the HTTP implementation.
        request_file = root / "dns-shutdown.json"
        request_file.write_text(json.dumps({"port": 1, "url": "https://dl.google.com/ok",
                                           "dns_failure": True}), encoding="utf-8")
        for iteration in range(50):
            result = subprocess.run([str(args.probe), str(request_file)],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 1 or not result.stdout.strip():
                raise RuntimeError(f"Resolver shutdown {iteration}: exit {result.returncode}: "
                                   f"{result.stdout}{result.stderr}")
            response = json.loads(result.stdout)
            if response["message"] != "Cannot resolve trusted host":
                raise RuntimeError(f"Resolver shutdown {iteration}: {response}")
        passed += 1
        print("50 resolver worker shutdown cycles: passed", flush=True)
        print(f"{passed} native HTTPS scenarios and production isolation passed")


if __name__ == "__main__":
    main()
