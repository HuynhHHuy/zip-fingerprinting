"""PH6-DATA-002: independent validation and real native invocation contracts."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zipfile
import zlib

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/generate_ground_truth.py"
spec = importlib.util.spec_from_file_location("generate_ground_truth", SCRIPT)
gt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gt)


def make_zip(path, name="a.txt", data=b"payload", extra=b""):
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.extra = extra
        archive.writestr(info, data)


@pytest.mark.parametrize("name", ["../a.txt", "/a.txt", "C:/a.txt", "a/../a.txt"])
def test_unsafe_archive_names_are_refused(tmp_path, name):
    path = tmp_path / "sample.zip"
    make_zip(path, name)
    with pytest.raises(ValueError, match="path"):
        gt.validate_archive(path, {"a.txt": b"payload"}, [], "cp1252")


def test_crc_wrong_payload_and_duplicate_names_are_refused(tmp_path):
    path = tmp_path / "sample.zip"
    make_zip(path)
    with pytest.raises(ValueError, match="payload"):
        gt.validate_archive(path, {"a.txt": b"different"}, [], "cp1252")
    path.write_bytes(path.read_bytes().replace(b"payload", b"payloae"))
    with pytest.raises(zipfile.BadZipFile):
        gt.validate_archive(path, {"a.txt": b"payload"}, [], "cp1252")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.txt", b"payload")
        with pytest.warns(UserWarning, match="Duplicate"):
            archive.writestr("a.txt", b"payload")
    with pytest.raises(ValueError, match="Duplicate"):
        gt.validate_archive(path, {"a.txt": b"payload"}, [], "cp1252")


@pytest.mark.parametrize("encoding_mode", ["utf8", "unicode_path", "legacy"])
def test_unicode_filename_decoding_and_directory_observations(tmp_path, encoding_mode):
    path = tmp_path / "sample.zip"
    logical = "가.txt"
    if encoding_mode == "utf8":
        make_zip(path, logical)
    else:
        raw = logical.encode("cp949")
        extra = b""
        if encoding_mode == "unicode_path":
            payload = b"\x01" + struct.pack("<I", zlib.crc32(raw)) + logical.encode("utf-8")
            extra = struct.pack("<HH", 0x7075, len(payload)) + payload
        make_zip(path, "xx.txt", extra=extra)
        path.write_bytes(path.read_bytes().replace(b"xx.txt", raw))
    report = gt.validate_archive(path, {logical: b"payload"}, ["empty"], "cp949")
    assert report["passed"] is True
    assert report["files"][0]["name"] == logical
    assert report["files"][0]["name_encoding"] == encoding_mode
    assert report["missing_directory_headers"] == ["empty"]


def test_unicode_path_with_wrong_crc_is_not_trusted(tmp_path):
    path = tmp_path / "sample.zip"
    payload = b"\x01" + struct.pack("<I", 0) + "가.txt".encode("utf-8")
    make_zip(path, "xx.txt", extra=struct.pack("<HH", 0x7075, len(payload)) + payload)
    with pytest.raises(ValueError, match="inventory"):
        gt.validate_archive(path, {"가.txt": b"payload"}, [], "cp1252")


def test_missing_tools_preserve_run_history_and_exit_two(tmp_path):
    first = gt.generate(tmp_path, {})
    second = gt.generate(tmp_path, {}, selected_tools=["7zip"], variants=["root"])
    assert first["run_id"] != second["run_id"]
    assert len(first["samples"]) == 12
    assert all(row["status"] == "skipped" for row in first["samples"])
    catalogue = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert catalogue == {"schema_version": 1, "runs": [first, second]}
    assert gt.exit_code(first) == 2
    saved = tmp_path / first["metadata_path"]
    assert json.loads(saved.read_text(encoding="utf-8")) == first


@pytest.mark.parametrize(
    "content", ["not json", '{"schema_version":2,"runs":[]}', '{"schema_version":1,"runs":[{}]}']
)
def test_bad_catalogue_is_refused_before_generating(tmp_path, content):
    (tmp_path / "metadata.json").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="catalogue"):
        gt.generate(tmp_path, {})
    assert (tmp_path / "metadata.json").read_text(encoding="utf-8") == content
    assert not (tmp_path / "ground_truth").exists()


def test_failed_real_process_is_recorded_not_generated(tmp_path):
    if os.name != "nt":
        pytest.skip("Requires Windows executable-version probing")
    report = gt.generate(tmp_path, {"7zip": Path(sys.executable)}, ["7zip"], ["root"])
    (record,) = report["samples"]
    assert record["status"] == "failed"
    assert record["commands"][-1]["returncode"] != 0
    assert gt.exit_code(report) == 1


def test_timeout_retains_partial_output(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 60, output=b"partial", stderr=b"diagnostic")

    monkeypatch.setattr(gt.subprocess, "run", timeout)
    commands = []
    with pytest.raises(RuntimeError):
        gt.run_command([sys.executable, "-c", "pass"], tmp_path, commands)
    (command,) = commands
    assert command["returncode"] is None
    assert command["stdout"] == "partial"
    assert command["stderr"] == "diagnostic"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only generator execution")
def test_broken_deflate_is_saved_as_failed_sample(tmp_path, monkeypatch):
    """A unit fault injection, not evidence of a native archiver run."""
    monkeypatch.setattr(gt, "tool_version", lambda path: "unit-test")

    def corrupt_archive(args, cwd, commands):
        destination = Path(args[-2])
        name = "set1/2021.JPG"
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, (cwd / name).read_bytes())
        payload = bytearray(destination.read_bytes())
        offset = 30 + len(name.encode("ascii"))
        payload[offset] = 7  # DEFLATE BTYPE=3 is invalid.
        destination.write_bytes(payload)
        commands.append({"argv": args, "returncode": 0, "stdout": "", "stderr": ""})

    monkeypatch.setattr(gt, "run_command", corrupt_archive)
    report = gt.generate(tmp_path, {"7zip": Path(sys.executable)}, ["7zip"], ["root"])
    assert report["samples"][0]["status"] == "failed"
    assert gt.exit_code(report) == 1
    assert (tmp_path / report["metadata_path"]).is_file()


def test_cli_bad_override_returns_nonzero_without_catalogue(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--data-dir",
            str(tmp_path),
            "--7zip",
            str(tmp_path / "missing.exe"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not (tmp_path / "metadata.json").exists()


@pytest.mark.parametrize("tool", ["7zip", "winrar", "powershell"])
def test_native_tool_generates_three_verified_variants(tmp_path, tool):
    tools = gt.discover_tools()
    if tool not in tools:
        pytest.skip(f"Requires installed Windows {tool}")
    data_dir = tmp_path / "native sample dữ liệu"
    report = gt.generate(data_dir, tools, [tool])
    assert gt.exit_code(report) == 0, report
    assert len(report["samples"]) == 3
    for sample in report["samples"]:
        assert sample["status"] == "generated", sample
        assert sample["validation"]["passed"] is True
        assert (
            sample["tool"]["application"]
            == {"7zip": "7-Zip", "winrar": "WinRAR", "powershell": "PowerShell Compress-Archive"}[
                tool
            ]
        )
        archive = data_dir / sample["path"]
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == sample["sha256"]
        names = [row["name"] for row in sample["validation"]["files"]]
        assert not any(name.endswith("manifest.json") for name in names)
        if sample["variant"] == "root":
            assert all(name.startswith("set1/") for name in names)
        elif sample["variant"] == "contents":
            assert not any(name.startswith("set1/") for name in names)
        else:
            assert all(name.startswith("auxiliary/") for name in names)
        assert all(row["mtime_ns"] == 1610364659000000000 for row in sample["source_times"])
        assert all(row["atime_ns"] == 1610364659000000000 for row in sample["source_times"])
