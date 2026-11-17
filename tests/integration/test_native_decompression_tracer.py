"""Pipeline failure contracts and separately identified native extraction tests."""

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import zipfile
import zlib

import pytest

from experiments import decompression_pipeline as pipeline
from experiments import windows_filetimes as ft
from scripts.simulate_modifications import discover_tools


def test_missing_tools_leave_report_and_no_native_measurements(tmp_path: Path) -> None:
    report = pipeline.trace(tmp_path, {}, "UTC", repeats=1)
    assert pipeline.exit_code(report) == 2
    assert not any(r["status"] == "measured" for r in report["measurements"])
    saved = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
    assert saved["coverage"]["dod_met"] is False
    markdown = Path(report["report_path"]).with_suffix(".md").read_text(encoding="utf-8")
    assert "skipped" in markdown and "dod_met: False" in markdown


@pytest.mark.skipif(os.name != "nt", reason="Windows executable and volume validation")
def test_invalid_override_is_failed_not_missing(tmp_path: Path) -> None:
    report = pipeline.trace(tmp_path, {"7zip": tmp_path / "missing.exe"}, "UTC", repeats=1)
    assert report["tools"]["7zip"]["status"] == "failed"
    assert pipeline.exit_code(report) == 1


def test_repeat_validation_precedes_output(tmp_path: Path) -> None:
    output = tmp_path / "not-created"
    with pytest.raises(ValueError, match="repeat"):
        pipeline.trace(output, {}, "UTC", repeats=0)
    assert not output.exists()


def test_bad_timezone_precedes_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="timezone"):
        pipeline.trace(tmp_path / "not-created", {}, "Not/A/Zone", repeats=1)
    assert not (tmp_path / "not-created").exists()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/drive", "a/../b", "a.", "CON"])
def test_unsafe_zip_is_rejected_before_extraction(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(name, b"payload")
    with pytest.raises(ValueError):
        pipeline.validate_zip(archive, {}, [], "no-extra", "UTC")


def test_symlink_archive_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    item = zipfile.ZipInfo("link")
    item.create_system = 3
    item.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(item, b"target")
    with pytest.raises(ValueError, match="link|type"):
        pipeline.validate_zip(archive, {"link": b"target"}, [], "no-extra", "UTC")


def test_existing_destination_is_never_reused(tmp_path: Path) -> None:
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(ValueError, match="exist"):
        pipeline.prepare_destination(destination)


def test_payload_mismatch_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("a.txt", b"wrong")
    with pytest.raises(ValueError, match="payload"):
        pipeline.validate_zip(archive, {"a.txt": b"expected"}, [], "no-extra", "UTC")


@pytest.mark.parametrize("location", ["LFH", "CDH"])
@pytest.mark.parametrize("alternate", ["../x.txt", "else.txt"])
def test_unicode_path_override_must_match_inventory(
    tmp_path: Path, location: str, alternate: str
) -> None:
    archive = tmp_path / "unicode-override.zip"
    name = b"safe.txt"
    body = b"\x01" + struct.pack("<I", zlib.crc32(name)) + name
    item = zipfile.ZipInfo(name.decode())
    item.extra = struct.pack("<HH", 0x7075, len(body)) + body
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(item, b"payload")
    raw = bytearray(archive.read_bytes())
    offset = 0 if location == "LFH" else raw.index(b"PK\x01\x02")
    start = offset + (30 if location == "LFH" else 46) + len(name) + 4 + 5
    raw[start : start + len(name)] = alternate.encode()
    archive.write_bytes(raw)
    with pytest.raises(ValueError, match="Unicode|path"):
        pipeline.validate_zip(archive, {"safe.txt": b"payload"}, [], "no-extra", "UTC")


def test_corrupt_deflate_retains_failed_profile(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fault injection after native compression is not native-success evidence."""
    if "7zip" not in native_tools:
        pytest.skip("Requires native source creator")
    original = pipeline.run_command

    def corrupt(args, cwd, commands):
        original(args, cwd, commands)
        if "a" not in args:
            return
        archive = Path(args[-2])
        with zipfile.ZipFile(archive) as stream:
            item = next(i for i in stream.infolist() if i.compress_type == zipfile.ZIP_DEFLATED)
        raw = bytearray(archive.read_bytes())
        name_len, extra_len = struct.unpack_from("<HH", raw, item.header_offset + 26)
        raw[item.header_offset + 30 + name_len + extra_len] = 0x07
        archive.write_bytes(raw)

    monkeypatch.setattr(pipeline, "run_command", corrupt)
    report = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(report) == 1
    saved = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
    assert saved["profiles"][0]["status"] == "failed"
    assert saved["profiles"][0]["commands"][-1]["returncode"] == 0
    assert saved["coverage"]["measured"] == 0


@pytest.fixture
def native_tools(tmp_path: Path) -> dict:
    if os.name != "nt":
        pytest.skip("Native Windows extraction")
    if ft.volume_info(tmp_path)["filesystem"] != "NTFS":
        pytest.skip("Native experiment requires NTFS")
    return discover_tools()


@pytest.mark.parametrize("tool", ["7zip", "winrar"])
def test_native_extractors_measure_both_profiles(
    tmp_path: Path, native_tools: dict, tool: str
) -> None:
    if "7zip" not in native_tools or tool not in native_tools:
        pytest.skip(f"Requires native 7zip source creator and {tool} extractor")
    report = pipeline.trace(
        tmp_path / "đo BMAC", native_tools, "Asia/Ho_Chi_Minh", selected_tools=[tool], repeats=1
    )
    assert pipeline.exit_code(report) == 0, report
    assert len(report["measurements"]) == 2
    for record in report["measurements"]:
        assert record["status"] == "measured", record
        assert record["validation"]["passed"] is True
        assert record["bounds"][0] <= record["bounds"][1]
        assert record["tool"] == tool
        kinds = {e["entry_type"] for e in record["analysis"]["entries"]}
        assert kinds >= {"file", "folder_with_files", "empty_folder"}
        for row in record["observations"]:
            assert all(isinstance(row[field], int) for field in pipeline.FIELDS)
            assert all(row["utc"][field].endswith("Z") for field in pipeline.FIELDS)
    assert report["coverage"]["dod_met"] is False  # One tool, one repeat is not the DoD matrix.
    markdown = Path(report["report_path"]).with_suffix(".md").read_text(encoding="utf-8")
    assert "measured" in markdown and "7zip" in markdown


def test_native_runs_are_separate_and_old_outputs_unchanged(
    tmp_path: Path, native_tools: dict
) -> None:
    if "7zip" not in native_tools:
        pytest.skip("Requires native 7zip")
    first = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    old = Path(first["report_path"]).read_bytes()
    second = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(first) == pipeline.exit_code(second) == 0
    assert first["run_directory"] != second["run_directory"]
    assert Path(first["report_path"]).read_bytes() == old


def test_failed_process_is_saved(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fault injection checks evidence retention, not native success."""
    if "7zip" not in native_tools:
        pytest.skip("Requires source preparation on native 7zip")

    def fail(args, cwd, commands):
        commands.append(
            {
                "argv": args,
                "cwd": str(cwd),
                "returncode": 9,
                "stdout": "partial",
                "stderr": "failed",
            }
        )
        raise RuntimeError("Injected process failure")

    monkeypatch.setattr(pipeline, "run_command", fail)
    report = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(report) == 1
    assert report["profiles"][0]["commands"][-1]["returncode"] == 9
    assert Path(report["report_path"]).is_file()
    markdown = Path(report["report_path"]).with_suffix(".md").read_text(encoding="utf-8")
    assert "failed" in markdown and "Injected process failure" in markdown


def test_timeout_is_saved(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    if "7zip" not in native_tools:
        pytest.skip("Requires native source preparation")

    def timeout(args, cwd, commands):
        commands.append(
            {
                "argv": args,
                "cwd": str(cwd),
                "returncode": None,
                "stdout": "partial",
                "stderr": "timeout",
            }
        )
        raise subprocess.TimeoutExpired(args, 60, output=b"partial")

    monkeypatch.setattr(pipeline, "run_command", timeout)
    report = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(report) == 1
    saved = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
    assert saved["profiles"][0]["commands"][-1]["stdout"] == "partial"


def test_snapshot_precedes_any_extracted_payload_reads(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    if "7zip" not in native_tools:
        pytest.skip("Requires native source preparation")
    original_snapshot = pipeline.snapshot_tree
    original_validate = pipeline.validate_extracted
    snapshots = []

    def snapshot(destination):
        result = original_snapshot(destination)
        snapshots.append(destination)
        return result

    def validate(destination, expected, directories):
        assert destination in snapshots
        return original_validate(destination, expected, directories)

    monkeypatch.setattr(pipeline, "snapshot_tree", snapshot)
    monkeypatch.setattr(pipeline, "validate_extracted", validate)
    report = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(report) == 0


def test_cli_invalid_repeat_returns_syntax_error(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "experiments.trace_decompression",
            "--dos-timezone",
            "UTC",
            "--repeat",
            "0",
            "--output",
            str(tmp_path / "unused"),
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "unused").exists()


def test_native_full_matrix_uses_same_archives(tmp_path: Path, native_tools: dict) -> None:
    if any(tool not in native_tools for tool in pipeline.TOOLS):
        pytest.skip("Requires both native extractors and the 7zip source creator")
    report = pipeline.trace(tmp_path, native_tools, "Asia/Ho_Chi_Minh")
    assert pipeline.exit_code(report) == 0, report
    assert report["coverage"]["measured"] == 12
    assert report["coverage"]["complete"] is True
    for profile in pipeline.PROFILES:
        records = [row for row in report["measurements"] if row["profile"] == profile]
        assert len(records) == 6
        assert len({row["zip_sha256"] for row in records}) == 1
        assert {row["tool"] for row in records} == set(pipeline.TOOLS)
    # Do not require a historical behavior on every future installed version.
    # The scientific gate remains explicit in coverage/--require-dod.
    assert pipeline.exit_code(report, require_dod=True) == (
        0 if report["coverage"]["dod_met"] else 2
    )


def test_corruption_after_snapshot_keeps_observations_and_fails(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    if "7zip" not in native_tools:
        pytest.skip("Requires native 7zip")
    original = pipeline.snapshot_tree

    def corrupt(destination):
        observations = original(destination)
        (destination / "set1/Study/textsm.txt").write_bytes(b"injected corruption")
        return observations

    monkeypatch.setattr(pipeline, "snapshot_tree", corrupt)
    report = pipeline.trace(tmp_path, native_tools, "UTC", ["7zip"], ["ntfs"], 1)
    assert pipeline.exit_code(report) == 1
    (record,) = report["measurements"]
    assert record["status"] == "failed"
    assert record["observations"]
    assert "payload" in record["reason"]


def test_non_ntfs_is_unsupported_not_fake_native_success(
    tmp_path: Path, native_tools: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline.ft, "volume_info", lambda path: {"filesystem": "exFAT"})
    report = pipeline.trace(tmp_path, native_tools, "UTC", repeats=1)
    assert pipeline.exit_code(report) == 2
    assert report["coverage"]["measured"] == 0


def test_native_junction_output_is_refused(tmp_path: Path, native_tools: dict) -> None:
    target = tmp_path / "target"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_bytes(b"untouched")
    link = tmp_path / "junction"
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(ValueError, match="reparse"):
            pipeline.trace(link, native_tools, "UTC", repeats=1)
        assert sentinel.read_bytes() == b"untouched"
        assert sorted(p.name for p in target.iterdir()) == ["keep.txt"]
    finally:
        link.rmdir()  # Remove only this temporary junction, not its target.


def test_dod_compares_sources_not_raw_clock_differences() -> None:
    """Synthetic coverage test, not evidence that any native behavior occurred."""
    report = {
        "selection": {
            "tools": list(pipeline.TOOLS),
            "profiles": list(pipeline.PROFILES),
            "repeat": 3,
        },
        "tools": {tool: {"status": "available"} for tool in pipeline.TOOLS},
        "profiles": [{"status": "generated"} for _ in pipeline.PROFILES],
        "measurements": [],
    }
    for profile in pipeline.PROFILES:
        for tool in pipeline.TOOLS:
            for repeat in (1, 2, 3):
                bmac = {
                    field: {
                        "status": "unique",
                        "labels": ["R"],
                        "observed": repeat * 100 + len(tool),
                    }
                    for field in pipeline.FIELDS
                }
                report["measurements"].append(
                    {
                        "status": "measured",
                        "profile": profile,
                        "tool": tool,
                        "repeat": repeat,
                        "zip_sha256": profile,
                        "analysis": {"entries": [{"path": "file", "bmac": bmac}]},
                    }
                )
    assert pipeline._coverage(report)["dod_met"] is False
    assert pipeline._coverage(report)["tool_differences"] == []
    for record in report["measurements"]:
        if record["tool"] == "7zip":
            record["analysis"]["entries"][0]["bmac"]["birth"]["labels"] = ["E"]
    assert pipeline._coverage(report)["dod_met"] is True
