"""Download pinned source archives for local development; never invokes Git."""
from pathlib import Path
import hashlib
import urllib.request

root = Path(__file__).resolve().parents[1] / ".deps"
root.mkdir(exist_ok=True)
for name, url, expected in (
    ("json-3.12.0.tar.gz", "https://codeload.github.com/nlohmann/json/tar.gz/refs/tags/v3.12.0", "4b92eb0c06d10683f7447ce9406cb97cd4b453be18d7279320f7b2f025c10187"),
    ("miniz-3.1.2.tar.gz", "https://codeload.github.com/richgel999/miniz/tar.gz/refs/tags/3.1.2", "98468f8924934b723276680f85238b6c78bf1f8b49b4459cc9b7214a20e2e9fb"),
):
    dest = root / name
    if not dest.exists():
        with urllib.request.urlopen(url, timeout=45) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise RuntimeError("Source archive exceeds limit")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("Source archive SHA-256 mismatch")
        dest.write_bytes(data)
    if hashlib.sha256(dest.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Cached source archive SHA-256 mismatch")
    print(name, hashlib.sha256(dest.read_bytes()).hexdigest())
