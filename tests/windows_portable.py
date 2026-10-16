"""Check built PE imports, embedded notices and startup without adjacent DLLs."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile


def imports(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError("Not a PE executable")
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise RuntimeError("Expected PE32+ executable")
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    section_table = optional + struct.unpack_from("<H", data, pe + 20)[0]

    def offset(rva):
        for index in range(section_count):
            section = section_table + index * 40
            address, size, start = struct.unpack_from("<III", data, section + 12)
            if address <= rva < address + size:
                return start + rva - address
        raise RuntimeError(f"Unmapped PE import RVA {rva}")

    result = set()
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    for directory_index, record_size, name_index in ((1, 20, 3), (13, 32, 1)):
        if directory_index >= directory_count:
            continue
        rva, size = struct.unpack_from("<II", data, optional + 112 + directory_index * 8)
        if not rva:
            continue
        start = offset(rva)
        for position in range(start, start + min(size, 1024 * record_size), record_size):
            record = struct.unpack_from("<" + "I" * (record_size // 4), data, position)
            if not any(record):
                break
            name_rva = record[name_index]
            if directory_index == 13 and not record[0] & 1:
                name_rva -= struct.unpack_from("<Q", data, optional + 24)[0]
            name_start = offset(name_rva)
            name_end = data.index(b"\0", name_start, name_start + 260)
            result.add(data[name_start:name_end].decode("ascii").lower())
        else:
            raise RuntimeError("Unterminated import directory")
    return result


def check_notices(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.FindResourceW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p]
    kernel.FindResourceW.restype = wintypes.HANDLE
    kernel.SizeofResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    kernel.SizeofResource.restype = wintypes.DWORD
    kernel.LoadResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    kernel.LoadResource.restype = wintypes.HANDLE
    kernel.LockResource.argtypes = [wintypes.HANDLE]
    kernel.LockResource.restype = ctypes.c_void_p
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    kernel.FreeLibrary.restype = wintypes.BOOL
    module = kernel.LoadLibraryExW(str(path), None, 0x02)  # Data only; no code runs.
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        for identifier in (101, 102, 103):
            resource = kernel.FindResourceW(module, identifier, 10)  # RT_RCDATA
            if not resource:
                raise RuntimeError(f"Missing embedded license {identifier}")
            size = kernel.SizeofResource(module, resource)
            address = kernel.LockResource(kernel.LoadResource(module, resource))
            if not address or size < 100:
                raise RuntimeError("Cannot read embedded license")
            notice = ctypes.string_at(address, size)
            if b"Copyright" not in notice or b"Permission is hereby granted" not in notice:
                raise RuntimeError("Incomplete embedded license")
    finally:
        kernel.FreeLibrary(module)


def main():
    executable = Path(sys.argv[1]).resolve()
    check_notices(executable)
    if sys.argv[2:] == ["--resources-only"]:
        print("Embedded project and library licenses: passed")
        return
    allowed = {"advapi32.dll", "bcrypt.dll", "crypt32.dll", "kernel32.dll",
               "msvcrt.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
               "shell32.dll", "ucrtbase.dll", "user32.dll", "ws2_32.dll",
               "winhttp.dll"}
    dependencies = imports(executable)
    unexpected = {name for name in dependencies if name not in allowed and
                  not name.startswith(("api-ms-win-", "ext-ms-win-"))}
    if not dependencies or unexpected:
        raise RuntimeError(f"Unexpected non-system imports: {sorted(unexpected)}")
    with tempfile.TemporaryDirectory(prefix="helium-standalone-") as temporary:
        isolated = Path(temporary) / executable.name
        shutil.copyfile(executable, isolated)
        environment = os.environ.copy()
        environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        for argument in ("--version", "--help"):
            result = subprocess.run([str(isolated), argument], cwd=temporary,
                                    env=environment, capture_output=True, timeout=15)
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError(f"Standalone {argument}: {result.returncode}: {result.stderr!r}")
        if list(Path(temporary).iterdir()) != [isolated]:
            raise RuntimeError("Standalone startup extracted additional files")
    print("System imports only; embedded licenses; standalone startup without DLLs: passed")


if __name__ == "__main__":
    main()
