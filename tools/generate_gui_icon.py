"""Regenerate the Windows ICO from the shared SVG (development tool only)."""

from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "build/icon-tools"))


def generate():
    import resvg_py  # Optional development dependency: resvg-py==0.2.6.

    source = ROOT / "ui/linux/io.github.KirioDEV.HeliumDRMFixer.svg"
    svg = ET.fromstring(source.read_text(encoding="utf-8"))
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    sizes = (16, 24, 32, 48, 64, 128, 256)
    images = []
    for size in sizes:
        svg.set("width", str(size))
        svg.set("height", str(size))
        images.append(resvg_py.svg_to_bytes(svg_string=ET.tostring(svg, encoding="unicode")))
    offset = 6 + 16 * len(images)
    entries = []
    for size, png in zip(sizes, images):
        if png[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", png[16:24]) != (size, size):
            raise ValueError("Unexpected rasterized icon dimensions")
        entries.append(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0,
                                   1, 32, len(png), offset))
        offset += len(png)
    destination = ROOT / "ui/windows/helium-drm-fixer.ico"
    destination.write_bytes(struct.pack("<HHH", 0, 1, len(images)) + b"".join(entries) + b"".join(images))
    print(f"Generated {destination}")


if __name__ == "__main__":
    generate()
