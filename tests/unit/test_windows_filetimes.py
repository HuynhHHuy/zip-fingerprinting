"""Raw Windows timestamp adapter: pure conversion and real filesystem checks."""

import ctypes
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys

import pytest

from experiments import windows_filetimes as ft


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "1601-01-01T00:00:00.0000000Z"),
        (1, "1601-01-01T00:00:00.0000001Z"),
        (116444736000000000, "1970-01-01T00:00:00.0000000Z"),
        (132548382591234567, "2021-01-11T11:30:59.1234567Z"),
        (132548382591234568, "2021-01-11T11:30:59.1234568Z"),
    ],
)
def test_filetime_utc_preserves_ticks(value: int, expected: str) -> None:
    assert ft.filetime_utc(value) == expected


@pytest.mark.parametrize("value", [-1, 1 << 64, (1 << 64) - 1])
def test_filetime_utc_rejects_unrepresentable_values(value: int) -> None:
    with pytest.raises(ValueError, match="FILETIME"):
        ft.filetime_utc(value)


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_filetime_utc_requires_integer(value: object) -> None:
    with pytest.raises(TypeError, match="integer"):
        ft.filetime_utc(value)  # type: ignore[arg-type]


def test_windows_api_not_loaded_on_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ft.sys, "platform", "linux")
    for call in [
        lambda: ft.read_bmac(Path("unused")),
        ft.now_filetime,
        lambda: ft.volume_info(Path("unused")),
        lambda: ft.set_source_times(Path("unused"), birth=1, modified=2, accessed=3),
    ]:
        with pytest.raises(OSError, match="Windows"):
            call()


def test_import_without_windows_dll_loader() -> None:
    """Simulate missing ctypes.WinDLL in a fresh interpreter, before import."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import ctypes
import importlib.util
import sys
if hasattr(ctypes, 'WinDLL'):
    del ctypes.WinDLL
sys.platform = 'linux'
spec = importlib.util.spec_from_file_location('adapter', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.filetime_utc(1) == '1601-01-01T00:00:00.0000001Z'
try:
    module.now_filetime()
except OSError as error:
    assert 'Windows' in str(error)
else:
    raise AssertionError('Native clock should reject unsupported platform')
""",
            str(Path(ft.__file__)),
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows APIs")
@pytest.mark.parametrize("directory", [False, True])
def test_native_bmac_roundtrip(tmp_path: Path, directory: bool) -> None:
    path = tmp_path / "dữ liệu nguồn"
    if directory:
        path.mkdir()
    else:
        path.write_bytes(b"payload")
    if ft.volume_info(path)["filesystem"] != "NTFS":
        pytest.skip("Exact timestamp roundtrip requires NTFS")
    # Distinct historical values prevent Modified/Changed aliasing from passing.
    ft.set_source_times(
        path, birth=132232158571234567, modified=132548382591234567, accessed=132863742557654321
    )
    actual = ft.read_bmac(path)
    assert set(actual) == {"birth", "modified", "accessed", "changed"}
    assert actual["birth"] == 132232158571234567
    assert actual["modified"] == 132548382591234567
    assert actual["accessed"] == 132863742557654321
    assert isinstance(actual["changed"], int)


def test_read_bmac_uses_separate_changed_field(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import contextmanager

    class API:
        def GetFileInformationByHandleEx(self, handle, kind, output, size):
            info = output._obj
            info.CreationTime, info.LastWriteTime = 11, 22
            info.LastAccessTime, info.ChangeTime = 33, 44
            return 1

    @contextmanager
    def handle(path, access):
        yield API(), 123

    monkeypatch.setattr(ft, "_handle", handle)
    assert ft.read_bmac(Path("unused")) == {
        "birth": 11,
        "modified": 22,
        "accessed": 33,
        "changed": 44,
    }


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows APIs")
def test_native_clock_and_volume(tmp_path: Path) -> None:
    lower = datetime.now(timezone.utc)
    value = ft.now_filetime()
    upper = datetime.now(timezone.utc)
    # Python 3.10 cannot parse the formatter's seven fractional digits. Only
    # this clock sanity check uses datetime precision; raw tick tests stay exact.
    observed = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    # Python 3.10/3.11 datetime.now can use a coarser Windows clock. This
    # sanity margin is only for this independent epoch/unit check, not R bounds.
    assert lower - timedelta(seconds=1) <= observed <= upper + timedelta(seconds=1)
    info = ft.volume_info(tmp_path)
    assert Path(info["root"]).is_dir()
    assert info["filesystem"]
    assert isinstance(info["serial"], int)
    file = tmp_path / "file.txt"
    file.write_bytes(b"payload")
    assert ft.volume_info(file) == info


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows APIs")
def test_native_missing_path_reports_windows_error(tmp_path: Path) -> None:
    with pytest.raises(OSError) as error:
        ft.read_bmac(tmp_path / "missing")
    assert error.value.winerror in {2, 3}


def test_basic_info_layout() -> None:
    assert ctypes.sizeof(ft._FileBasicInfo) == 40


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows error reporting")
@pytest.mark.parametrize("operation", ["read", "set", "volume"])
def test_failed_query_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """Fault injection checks cleanup, not native measurement evidence."""
    closed = []

    class API:
        def CreateFileW(self, *args):
            return 123

        def CloseHandle(self, handle):
            closed.append(handle)
            return 1

        def GetFileInformationByHandleEx(self, *args):
            ctypes.set_last_error(5)
            return 0

        def SetFileTime(self, *args):
            ctypes.set_last_error(5)
            return 0

        def GetVolumePathNameW(self, *args):
            ctypes.set_last_error(5)
            return 0

    monkeypatch.setattr(ft, "_kernel32", lambda: API())
    with pytest.raises(OSError) as error:
        if operation == "read":
            ft.read_bmac(tmp_path)
        elif operation == "set":
            ft.set_source_times(tmp_path, birth=1, modified=2, accessed=3)
        else:
            ft.volume_info(tmp_path)
    assert error.value.winerror == 5
    assert closed == [123]


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows setter")
@pytest.mark.parametrize("value", [0, -1, 1 << 63, (1 << 64) - 1, True, 1.5])
def test_source_setter_rejects_control_values_without_changing_source(
    tmp_path: Path, value: int
) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"evidence")
    before = ft.read_bmac(source)
    with pytest.raises((ValueError, TypeError)):
        ft.set_source_times(source, birth=value, modified=1, accessed=2)
    assert ft.read_bmac(source) == before
