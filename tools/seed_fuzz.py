"""Create small synthetic parser seeds, containing no executable CDM."""
from pathlib import Path
import io
import json
import struct
import sys
import zipfile

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
for name, selector, content in (
    ("path", 0, b"_platform_specific/linux_x64/libwidevinecdm.so"),
    ("traversal", 0, b"dir/../../escape"),
    ("version", 1, b"4.10.3112.0"),
    ("json", 2, b'{"version":"4.10.3112.0"}'),
    ("duplicate-json", 2, b'{"a":1,"a":2}'),
    ("crx", 3, b"Cr24" + struct.pack("<II", 3, 3) + b"\x0a\x01xPK\x03\x04"),
    ("update", 5, b'{"response":{"protocol":"4.0","apps":[]}}'),
):
    (root / name).write_bytes(bytes([selector]) + content)
binary = bytearray(128)
binary[:7] = b"\x7fELF\x02\x01\x01"
binary[16] = 3
binary[18] = 62
archive = io.BytesIO()
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_file:
    zip_file.writestr("manifest.json", json.dumps({"version": "1.2.3.4"}))
    zip_file.writestr("libwidevinecdm.so", binary)
(root / "zip").write_bytes(bytes([4]) + archive.getvalue())
