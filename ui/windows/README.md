# Windows application icon

`helium-drm-fixer.ico` is generated from
`../linux/io.github.KirioDEV.HeliumDRMFixer.svg` at 16, 24, 32, 48, 64, 128 and
256 pixels. Keep the SVG as the source and regenerate the ICO when it changes.

The ICO is an Explorer/EXE resource; Slint embeds the original SVG as the window
icon. Both are project assets covered by the project license.

Generation uses `resvg-py==0.2.6` to rasterize the SVG at each size and writes a
standard ICO directory with those seven PNG payloads. The rasterizer is a
development tool and is not part of the app or required for normal builds.

From the repository root:

```powershell
python -m pip install --target build/icon-tools resvg-py==0.2.6
python tools/generate_gui_icon.py
```
