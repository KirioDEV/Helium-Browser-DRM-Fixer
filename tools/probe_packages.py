"""Fetch official test inputs only; never installs or loads Widevine binaries."""
from pathlib import Path
import hashlib
import json
import urllib.request
from urllib.parse import urlsplit

root = Path(__file__).resolve().parents[1] / ".deps"
root.mkdir(exist_ok=True)
app_id = "oimompecagnajdejgnnjijobebaeigek"
for platform in ("win", "linux"):
    body = {"request": {"@os": "", "@updater": "", "acceptformat": "crx3,download,puff,run,xz,zucc",
        "apps": [{"appid": app_id, "installsource": "ondemand", "updatecheck": {}, "version": "0.0.0.0"}],
        "dedup": "cr", "ismachine": False, "arch": "x64", "os": {"arch": "x64", "platform": platform},
        "protocol": "4.0", "updaterversion": "999.0.0.0"}}
    request = urllib.request.Request("https://update.googleapis.com/service/update2/json",
        json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("Metadata exceeds limit")
    (root / f"google-{platform}.json").write_bytes(raw)
    metadata = json.loads(raw.decode().removeprefix(")]}'"))
    app = next(a for a in metadata["response"]["apps"] if a["appid"] == app_id)
    check = app["updatecheck"]
    print(platform, "status", check["status"], "version", check.get("nextversion"))
    for pipeline in check.get("pipelines", []):
        ops = pipeline["operations"]
        print("operations", [op["type"] for op in ops])
        if len(ops) != 2 or ops[0]["type"] != "download" or ops[1]["type"] != "crx3":
            continue
        checksum = ops[0]["out"]["sha256"]
        url = next(u["url"] for u in ops[0]["urls"] if u["url"].startswith("https://"))
        parsed = urlsplit(url)
        if parsed.hostname not in {"dl.google.com", "edgedl.me.gvt1.com"} or parsed.port not in (None, 443):
            raise RuntimeError(f"Unapproved host: {parsed.hostname}")
        print("download host", parsed.hostname, "sha256", checksum)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise RuntimeError("Unexpected download redirect")
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(url, timeout=30) as response:
            data = response.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != checksum.lower():
            raise RuntimeError("Package size or SHA-256 mismatch")
        (root / f"widevine-{platform}.crx3").write_bytes(data)
        print("saved verified-hash package", len(data), "bytes")
        break
