"""Read native Windows BMAC timestamps without opening file payloads.

FILETIME values are integer ticks of 100 ns since 1601-01-01 UTC. Changed
comes from FILE_BASIC_INFO.ChangeTime, not LastWriteTime or Python st_ctime.
The setter is for disposable experiment sources only; never use it on evidence.
"""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
import sys
from typing import Any, Iterator

_TICKS_PER_SECOND = 10_000_000
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_READ_ATTRIBUTES = 0x80
_WRITE_ATTRIBUTES = 0x100


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", ctypes.c_uint32),
    ]


def filetime_utc(value: int) -> str:
    """Format FILETIME exactly, raising ValueError outside the UTC display range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("FILETIME must be an integer")
    if not 0 <= value < 1 << 64:
        raise ValueError("FILETIME must be an unsigned 64-bit integer")
    seconds, fraction = divmod(value, _TICKS_PER_SECOND)
    try:
        stamp = _EPOCH + timedelta(seconds=seconds)
    except OverflowError as exc:
        raise ValueError("FILETIME is outside the representable UTC date range") from exc
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:07d}Z"


@lru_cache(maxsize=1)
def _kernel32() -> Any:
    """Load and bind Win32 only on first native call."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER
    signatures = {
        "CreateFileW": (
            [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ],
            wintypes.HANDLE,
        ),
        "GetFileInformationByHandleEx": (
            [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            wintypes.BOOL,
        ),
        "SetFileTime": (
            [wintypes.HANDLE, pointer(_FileTime), pointer(_FileTime), pointer(_FileTime)],
            wintypes.BOOL,
        ),
        "GetSystemTimePreciseAsFileTime": ([pointer(_FileTime)], None),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        "GetVolumePathNameW": (
            [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD],
            wintypes.BOOL,
        ),
        "GetVolumeInformationByHandleW": (
            [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                pointer(wintypes.DWORD),
                pointer(wintypes.DWORD),
                pointer(wintypes.DWORD),
                wintypes.LPWSTR,
                wintypes.DWORD,
            ],
            wintypes.BOOL,
        ),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes = arguments
        function.restype = result
    return kernel


def _require_windows() -> None:
    if sys.platform != "win32":
        raise OSError("Native FILETIME measurement requires Windows")


@contextmanager
def _handle(path: Path, access: int) -> Iterator[tuple[Any, int]]:
    _require_windows()
    kernel = _kernel32()
    # OPEN_EXISTING; share read/write/delete; BACKUP_SEMANTICS supports folders.
    handle = kernel.CreateFileW(str(path.absolute()), access, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield kernel, handle
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def read_bmac(path: Path) -> dict[str, int]:
    """Read Birth/Modified/Accessed/Changed as raw 100 ns values, metadata only."""
    with _handle(path, _READ_ATTRIBUTES) as (kernel, handle):
        info = _FileBasicInfo()
        if not kernel.GetFileInformationByHandleEx(
            handle, 0, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "birth": info.CreationTime,
            "modified": info.LastWriteTime,
            "accessed": info.LastAccessTime,
            "changed": info.ChangeTime,
        }


def now_filetime() -> int:
    """Read the Windows precise UTC wall clock for extraction start/end bounds."""
    _require_windows()
    value = _FileTime()
    _kernel32().GetSystemTimePreciseAsFileTime(ctypes.byref(value))
    return (int(value.high) << 32) | int(value.low)


def volume_info(path: Path) -> dict[str, str | int]:
    """Query the actual existing target's volume, following junctions/mounts."""
    _require_windows()
    target = path.resolve(strict=True)
    with _handle(target, _READ_ATTRIBUTES) as (kernel, handle):
        root = ctypes.create_unicode_buffer(32768)
        if not kernel.GetVolumePathNameW(str(target), root, len(root)):
            raise ctypes.WinError(ctypes.get_last_error())
        filesystem = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        if not kernel.GetVolumeInformationByHandleW(
            handle, None, 0, ctypes.byref(serial), None, None, filesystem, len(filesystem)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"root": root.value, "filesystem": filesystem.value, "serial": serial.value}


def set_source_times(path: Path, *, birth: int, modified: int, accessed: int) -> None:
    """Set B/M/A on a disposable source. Changed is left to the filesystem.

    The caller owns source/evidence separation. Zero and sentinel/negative times
    are rejected because SetFileTime treats them as control values, not dates.
    """
    _require_windows()
    values = []
    for value in (birth, accessed, modified):  # Win32 argument order differs from BMAC.
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("Source FILETIME must be an integer")
        if not 0 < value < 1 << 63:
            raise ValueError("Source FILETIME must be positive and below 2**63")
        values.append(_FileTime(value & 0xFFFFFFFF, value >> 32))
    with _handle(path, _WRITE_ATTRIBUTES) as (kernel, handle):
        if not kernel.SetFileTime(handle, *(ctypes.byref(value) for value in values)):
            raise ctypes.WinError(ctypes.get_last_error())
