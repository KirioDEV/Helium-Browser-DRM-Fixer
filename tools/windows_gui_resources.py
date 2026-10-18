"""Store GUI notices inside a Windows executable without extracting them at startup."""

import ctypes
from ctypes import wintypes
import io
import json
import re
import zipfile

NOTICE_RESOURCE = 104


def read_resource(executable, identifier, kind=10):
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
    module = kernel.LoadLibraryExW(str(executable), None, 0x02)  # Data only.
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        resource = kernel.FindResourceW(module, identifier, kind)
        if not resource:
            raise ctypes.WinError(ctypes.get_last_error())
        size = kernel.SizeofResource(module, resource)
        address = kernel.LockResource(kernel.LoadResource(module, resource))
        if not size or not address:
            raise RuntimeError("Empty/unreadable Windows resource")
        return ctypes.string_at(address, size)
    finally:
        kernel.FreeLibrary(module)


def embed_notices(executable, data):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    kernel.BeginUpdateResourceW.restype = wintypes.HANDLE
    kernel.UpdateResourceW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      wintypes.WORD, ctypes.c_void_p, wintypes.DWORD]
    kernel.UpdateResourceW.restype = wintypes.BOOL
    kernel.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    kernel.EndUpdateResourceW.restype = wintypes.BOOL
    handle = kernel.BeginUpdateResourceW(str(executable), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_string_buffer(data)
        if not kernel.UpdateResourceW(handle, 10, NOTICE_RESOURCE, 0, buffer, len(data)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.EndUpdateResourceW(handle, False):
            raise ctypes.WinError(ctypes.get_last_error())
        handle = None
    finally:
        if handle:
            kernel.EndUpdateResourceW(handle, True)
    if read_resource(executable, NOTICE_RESOURCE) != data:
        raise RuntimeError("Embedded GUI notice archive differs from its input")


def verify_notices(executable):
    with zipfile.ZipFile(io.BytesIO(read_resource(executable, NOTICE_RESOURCE))) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Corrupt embedded GUI notice archive")
        required = {"LICENSE", "README.md", "SECURITY.md", "THIRD_PARTY.md",
                    "licenses/rust/inventory.json", "licenses/rust/Cargo.lock",
                    "licenses/rust/rust-standard-library/COPYRIGHT-library.html",
                    "io.github.KirioDEV.HeliumDRMFixer.svg"}
        if not required.issubset(archive.namelist()):
            raise RuntimeError("Incomplete embedded GUI notices")
        inventory = json.loads(archive.read("licenses/rust/inventory.json"))
        if inventory["target"] != "x86_64-pc-windows-msvc" or not inventory["packages"]:
            raise RuntimeError("Unexpected GUI dependency inventory")
        for package in inventory["packages"]:
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", package["name"] + "-" + package["version"])
            prefix = f"licenses/rust/{name}/"
            for name in package["notices"]:
                archive.getinfo(prefix + name)
            for notice in package["upstream_notices"]:
                archive.getinfo(prefix + notice["filename"])
    # Check that updating resources preserved the seven-size application icon.
    icon = read_resource(executable, 1, 14)  # RT_GROUP_ICON
    if int.from_bytes(icon[4:6], "little") != 7:
        raise RuntimeError("Missing multi-resolution GUI icon")
