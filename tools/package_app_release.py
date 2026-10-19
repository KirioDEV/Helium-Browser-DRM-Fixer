"""Build bounded app-release ZIPs and optionally sign their exact manifest bytes.

Private signing keys are supplied explicitly and are never copied to output.
Without a key the output is an unsigned candidate, unsuitable for self-update.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

REPOSITORY = "KirioDEV/Helium-Browser-DRM-Fixer"
DOMAIN = b"Helium DRM Fixer app update manifest v1\0"
PLATFORMS = ("windows-x64", "linux-x86_64-ubuntu24.04")
LIMIT = 128 * 1024 * 1024
SHARE = "share/helium-drm-fixer/"
DOCUMENTS = {SHARE + name for name in (
    "README.md", "LICENSE", "SECURITY.md", "THIRD_PARTY.md",
    "licenses/nlohmann-json-MIT.txt", "licenses/miniz-MIT.txt")}


def app_identity(gui=False):
    return "helium-drm-fixer-gui" if gui else "helium-drm-fixer-cpp"


def app_executable(platform, gui=False):
    if gui:
        return "bin/helium_drm_fixer_gui" + (".exe" if platform == "windows-x64" else ".AppImage")
    return "bin/helium_drm_fixer" + (".exe" if platform == "windows-x64" else "")


def package_name(version, platform, gui=False):
    return f"{app_identity(gui)}-{version}-{platform}.zip"
RUNTIMES = {"bin/" + name for name in (
    "libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll")}


def version_parts(version):
    if not re.fullmatch(r"(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})", version):
        raise ValueError("Version must have three canonical numeric components")
    if any(int(part) > 0xffffffff for part in version.split(".")):
        raise ValueError("Version component overflow")


def linked(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def safe_directory(path):
    path = Path(os.path.abspath(path))
    for ancestor in (*reversed(path.parents), path):
        info = ancestor.lstat()
        if linked(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Release directories must not contain links/reparse points")
    return path


def rsa_signature_size(key):
    def der(data, tag):
        if len(data) < 2 or data[0] != tag:
            raise ValueError("Invalid RSA public DER key")
        size, pos = data[1], 2
        if size & 0x80:
            count = size & 0x7f
            if not 0 < count <= 2 or len(data) < 2 + count or data[2] == 0:
                raise ValueError("Noncanonical RSA public DER key")
            size = int.from_bytes(data[2:2 + count], "big")
            pos += count
            if size < 128:
                raise ValueError("Noncanonical DER length")
        if size > len(data) - pos:
            raise ValueError("Truncated RSA key")
        return data[pos:pos + size], data[pos + size:]

    if len(key) > 1024:
        raise ValueError("Oversized public key")
    sequence, rest = der(key, 0x30)
    algorithm, sequence = der(sequence, 0x30)
    oid, algorithm = der(algorithm, 6)
    null, algorithm = der(algorithm, 5)
    bits, sequence = der(sequence, 3)
    if rest or algorithm or null or sequence or oid != bytes.fromhex("2a864886f70d010101") or not bits or bits[0]:
        raise ValueError("Key must be RSA SubjectPublicKeyInfo")
    rsa, rest = der(bits[1:], 0x30)
    modulus, rsa = der(rsa, 2)
    exponent, rsa = der(rsa, 2)
    if rest or rsa or len(modulus) not in (385, 513) or modulus[0] or not modulus[1] & 0x80 or exponent != b"\x01\x00\x01":
        raise ValueError("Use RSA-3072/4096 with exponent 65537")
    return len(modulus) - 1


def openssl(arguments, data=None, cwd=None):
    result = subprocess.run(arguments, input=data if data is not None else b"",
                            capture_output=True, timeout=30, cwd=cwd)
    if result.returncode:
        raise ValueError("OpenSSL failed; check the key, algorithm and passphrase environment")
    return result.stdout


def sign_manifest(manifest, key, openssl_path, password_env=None, trusted_public=None):
    if os.path.dirname(openssl_path):
        openssl_path = os.path.abspath(openssl_path)
    key = Path(key).resolve(strict=True)
    # Some Windows OpenSSL distributions use narrow file APIs. An ASCII key
    # basename relative to a wide-character process cwd supports Unicode folders.
    if not key.name.isascii():
        raise ValueError("Use an ASCII filename for the OpenSSL signing key")
    password = []
    if password_env:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", password_env) or password_env not in os.environ:
            raise ValueError("Missing/invalid passphrase environment variable")
        password = ["-passin", "env:" + password_env]
    public = openssl([openssl_path, "pkey", "-in", key.name, *password,
                      "-pubout", "-outform", "DER"], cwd=key.parent)
    size = rsa_signature_size(public)
    if trusted_public is not None and public != trusted_public:
        raise ValueError("Signing key does not match the pinned public release key")
    signature = openssl([openssl_path, "dgst", "-sha256", "-sign", key.name,
                         *password, "-sigopt", "rsa_padding_mode:pkcs1"], DOMAIN + manifest, cwd=key.parent)
    if len(signature) != size:
        raise ValueError("Invalid RSA signature size")
    return signature


def read_regular(path, limit=64 * 1024 * 1024):
    before = path.lstat()
    if linked(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("Release inputs must be bounded, regular files without links")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
    if linked(opened) or identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) != opened.st_size:
        raise ValueError("Release input changed while being read")
    return data


def validate_binary(data, windows, library=False):
    if len(data) < 64:
        raise ValueError("Truncated release binary")
    if windows:
        offset = int.from_bytes(data[60:64], "little")
        if (data[:2] != b"MZ" or offset > len(data) - 26 or
                data[offset:offset + 6] != b"PE\0\0\x64\x86" or
                data[offset + 24:offset + 26] != b"\x0b\x02" or
                bool(data[offset + 23] & 0x20) != library):
            raise ValueError("Release binary is not the expected x64 PE32+ image")
    elif data[:7] != b"\x7fELF\x02\x01\x01" or data[16:20] not in (b"\x02\0\x3e\0", b"\x03\0\x3e\0"):
        raise ValueError("Release binary is not x86_64 ELF")


def build_release(staging, version, platform, output, signing_key=None,
                  openssl_path="openssl", password_env=None, gui=False):
    version_parts(version)
    if password_env and not signing_key:
        raise ValueError("A passphrase environment requires a signing key")
    if platform not in PLATFORMS:
        raise ValueError("Unsupported release platform")
    staging, output = safe_directory(staging), safe_directory(output)
    if output == staging or output.is_relative_to(staging) or staging.is_relative_to(output):
        raise ValueError("Staging and output must be separate directory trees")
    if signing_key and (Path(signing_key).resolve().is_relative_to(staging) or
                        Path(signing_key).resolve().is_relative_to(output)):
        raise ValueError("Keep private signing keys outside staging and release output")
    windows = platform == "windows-x64"
    executable = app_executable(platform, gui)
    allowed = DOCUMENTS | {executable} | (RUNTIMES if windows and not gui else set())
    data, pending, total = {}, [staging], 0
    while pending:
        for path in sorted(pending.pop().iterdir()):
            info = path.lstat()
            if linked(info):
                raise ValueError("Links/reparse points are forbidden in staging")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            name = path.relative_to(staging).as_posix()
            if name not in allowed or name.lower() in {item.lower() for item in data}:
                raise ValueError("Unknown or colliding staged file: " + name)
            content = read_regular(path)
            if name == executable or name in RUNTIMES:
                validate_binary(content, windows, name in RUNTIMES)
                if gui and not windows and content[8:11] != b"AI\x02":
                    raise ValueError("GUI updates require a Type-2 AppImage")
            total += len(content)
            if total > LIMIT or len(data) >= 256:
                raise ValueError("Release contents exceed limits")
            data[name] = content
    required = {executable, SHARE + "README.md", SHARE + "LICENSE",
                SHARE + "licenses/nlohmann-json-MIT.txt", SHARE + "licenses/miniz-MIT.txt"}
    if not required <= data.keys() or (windows and len(data.keys() & RUNTIMES) not in (0, 3)):
        raise ValueError("Missing app binary, licenses, README or MinGW runtime files")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
        for name, content in sorted(data.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if name == executable else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            zipped.writestr(entry, content, compresslevel=9)
    package = archive.getvalue()
    if not 0 < len(package) <= LIMIT:
        raise ValueError("Release ZIP exceeds size limit")
    name = package_name(version, platform, gui)
    manifest = json.dumps({
        "schema_version": 1, "app_id": app_identity(gui), "repository": REPOSITORY,
        "version": version, "platform": platform,
        "package": {"name": name, "size": len(package), "sha256": hashlib.sha256(package).hexdigest()},
        "files": [{"path": path, "size": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                   "executable": path == executable} for path, content in sorted(data.items())]
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(manifest) > 65536:
        raise ValueError("Release manifest exceeds size limit")
    artifacts = {name: package, name + ".manifest.json": manifest}
    if signing_key:
        artifacts[name + ".manifest.sig"] = sign_manifest(manifest, signing_key, openssl_path, password_env)
    created = []
    try:
        for filename, content in artifacts.items():
            with (output / filename).open("xb") as stream:
                created.append(output / filename)
                stream.write(content)
    except BaseException:
        for path in created:
            path.unlink()
        raise
    return [output / filename for filename in artifacts]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", choices=PLATFORMS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--key-password-env")
    args = parser.parse_args()
    try:
        paths = build_release(args.staging, args.version, args.platform, args.output,
                              args.signing_key, args.openssl, args.key_password_env, args.gui)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Release packaging failed: {error}\n")
    print("Signed release files:" if args.signing_key else "Unsigned candidate (not installable as trusted update):")
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
