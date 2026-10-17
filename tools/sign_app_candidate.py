"""Inspect unsigned CI candidates or sign their exact existing bytes locally.

Does not extract or execute ZIP contents, access Git or publish a release.
The expected public key is supplied separately, never taken from the candidate.
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
import tempfile
import zipfile
import zlib

from package_app_release import (DOCUMENTS, DOMAIN, LIMIT, PLATFORMS, REPOSITORY, SHARE,
                                 openssl, read_regular, rsa_signature_size, safe_directory,
                                 sign_manifest, validate_binary, version_parts)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "Duplicate manifest key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Nonfinite JSON number")

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=invalid_constant)
        pending = [(result, 0)]
        while pending:
            value, depth = pending.pop()
            require(depth <= 32, "Manifest nesting limit exceeded")
            if isinstance(value, dict):
                pending.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
        return result
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid manifest encoding/nesting") from error


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "Invalid SHA-256")
    return value


def bounded(value, maximum):
    require(type(value) is int and 0 <= value <= maximum, "Invalid inventory size")
    return value


def inspect_candidate(candidate):
    candidate = Path(os.path.abspath(candidate))
    safe_directory(candidate.parent)
    manifest_path = candidate.with_name(candidate.name + ".manifest.json")
    manifest_bytes = read_regular(manifest_path, 65536)
    value = strict_json(manifest_bytes)
    require(isinstance(value, dict) and set(value) == {
        "schema_version", "app_id", "repository", "version", "platform", "package", "files"
    }, "Invalid candidate manifest schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and
            value["app_id"] == "helium-drm-fixer-cpp" and value["repository"] == REPOSITORY,
            "Wrong candidate identity")
    require(isinstance(value["version"], str) and isinstance(value["platform"], str),
            "Invalid candidate version/platform")
    version_parts(value["version"])
    platform = value["platform"]
    require(platform in PLATFORMS, "Unsupported candidate platform")
    expected_name = f"helium-drm-fixer-cpp-{value['version']}-{platform}.zip"
    package = value["package"]
    require(isinstance(package, dict) and set(package) == {"name", "size", "sha256"} and
            package["name"] == expected_name == candidate.name, "Candidate name mismatch")
    size = bounded(package["size"], LIMIT)
    require(size > 0, "Empty candidate package")
    package_bytes = read_regular(candidate, LIMIT)
    require(len(package_bytes) == size and hashlib.sha256(package_bytes).hexdigest() == digest(package["sha256"]),
            "Candidate ZIP size/hash mismatch")
    windows = platform == "windows-x64"
    executable = "bin/helium_drm_fixer" + (".exe" if windows else "")
    allowed = DOCUMENTS | {executable}
    files = value["files"]
    require(isinstance(files, list) and 0 < len(files) <= 256, "Invalid candidate file inventory")
    inventory, total = {}, 0
    for file in files:
        require(isinstance(file, dict) and set(file) == {"path", "size", "sha256", "executable"},
                "Invalid candidate file entry")
        path = file["path"]
        require(isinstance(path, str) and path in allowed and path not in inventory,
                "Unknown/duplicate path or external runtime DLL in candidate")
        total += bounded(file["size"], 64 * 1024 * 1024)
        require(total <= LIMIT, "Candidate expanded size limit exceeded")
        digest(file["sha256"])
        require(type(file["executable"]) is bool and file["executable"] == (path == executable),
                "Wrong executable inventory flag")
        inventory[path] = file
    require({executable, SHARE + "README.md", SHARE + "LICENSE", SHARE + "licenses/miniz-MIT.txt",
             SHARE + "licenses/nlohmann-json-MIT.txt"} <= inventory.keys(), "Required candidate files missing")
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
            entries = archive.infolist()
            require(len(entries) == len(inventory), "ZIP inventory count mismatch")
            seen = set()
            for entry in entries:
                path = entry.filename
                require(path in inventory and path not in seen and path == entry.orig_filename and not entry.is_dir() and
                        not entry.flag_bits & ~(0x800 | 8) and
                        entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                        "Unsafe ZIP entry")
                seen.add(path)
                file = inventory[path]
                mode = stat.S_IFREG | (0o755 if file["executable"] else 0o644)
                require(entry.create_system == 3 and entry.external_attr >> 16 == mode and
                        not entry.external_attr & 0x10 and entry.file_size == file["size"],
                        "ZIP size/type/mode mismatch")
                with archive.open(entry) as stream:
                    data = stream.read(file["size"] + 1)
                require(len(data) == file["size"] and hashlib.sha256(data).hexdigest() == file["sha256"],
                        "ZIP file hash/size mismatch")
                if path == executable:
                    validate_binary(data, windows)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error) as error:
        raise ValueError("Invalid candidate ZIP") from error
    return value, manifest_bytes, package_bytes


def sign_candidate(candidate, public_key, private_key, output, openssl_path="openssl", password_env=None):
    value, manifest, package = inspect_candidate(candidate)
    public_key = Path(os.path.abspath(public_key))
    safe_directory(public_key.parent)
    public = read_regular(public_key, 1024)
    rsa_signature_size(public)
    output = Path(os.path.abspath(output))
    safe_directory(output.parent)
    require(not os.path.lexists(output), "Choose a new, nonexistent output directory")
    private_key = Path(private_key).resolve(strict=True)
    require(not private_key.is_relative_to(output) and
            not private_key.is_relative_to(Path(os.path.abspath(candidate)).parent),
            "Keep the private key outside candidate and output directories")
    signature = sign_manifest(manifest, private_key, openssl_path, password_env, public)
    # Verify against the separately pinned key before producing release output.
    # ASCII filenames relative to a Unicode-capable cwd also support Git OpenSSL.
    if os.path.dirname(openssl_path):
        openssl_path = os.path.abspath(openssl_path)
    with tempfile.TemporaryDirectory(prefix="helium-sign-check-") as temporary:
        directory = Path(temporary)
        (directory / "public.der").write_bytes(public)
        (directory / "signature.bin").write_bytes(signature)
        openssl([openssl_path, "dgst", "-sha256", "-verify", "public.der", "-keyform", "DER",
                 "-signature", "signature.bin", "-sigopt", "rsa_padding_mode:pkcs1"],
                DOMAIN + manifest, cwd=directory)
    output.mkdir(mode=0o700)
    name = value["package"]["name"]
    for filename, content in ((name, package), (name + ".manifest.json", manifest),
                              (name + ".manifest.sig", signature)):
        with (output / filename).open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    # An interrupted/failed output is retained for inspection, never overwritten
    # on a retry. No private key or passphrase is copied to release output.
    return [output / (name + suffix) for suffix in ("", ".manifest.json", ".manifest.sig")]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true")
    mode.add_argument("--signing-key", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--key-password-env")
    args = parser.parse_args()
    try:
        if args.check_only:
            require(not args.output and not args.public_key and not args.key_password_env,
                    "--check-only only accepts a candidate; it does not verify a signature")
            value, _, _ = inspect_candidate(args.candidate)
            print(json.dumps({"state": "unsigned_candidate_checked", "version": value["version"],
                              "platform": value["platform"], "package_sha256": value["package"]["sha256"],
                              "signature_verified": False}, sort_keys=True))
        else:
            require(args.public_key and args.output, "Signing requires --public-key and --output")
            paths = sign_candidate(args.candidate, args.public_key, args.signing_key, args.output,
                                   args.openssl, args.key_password_env)
            print("Signed candidate; verify with the native app before publishing:")
            for path in paths:
                print(path)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Candidate preparation failed: {error}\n")


if __name__ == "__main__":
    main()
