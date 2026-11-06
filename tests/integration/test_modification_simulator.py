"""Native simulator contracts; unavailable proprietary tools are explicitly skipped."""

import importlib.util
import json
from pathlib import Path
import sys
import zipfile

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "simulate_modifications.py"
spec = importlib.util.spec_from_file_location("simulate_modifications", SCRIPT)
simulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(simulator)


def test_missing_tools_are_skipped_and_runs_do_not_overwrite(tmp_path):
    first = simulator.simulate(tmp_path, {}, ["A", "B", "C"])
    second = simulator.simulate(tmp_path, {}, ["A"])
    assert first["run_directory"] != second["run_directory"]
    assert [r["status"] for r in first["scenarios"]] == ["skipped"] * 3
    assert first["coverage"] == {"case1": False, "case2": False, "dod_met": False}
    assert "winrar" in first["scenarios"][0]["reason"]
    saved = json.loads((Path(first["run_directory"]) / "metadata.json").read_text())
    assert saved == first


@pytest.mark.parametrize("operation", ["add", "modify", "delete"])
def test_payload_validation_rejects_unrelated_changes(tmp_path, operation):
    before, after = tmp_path / "before.zip", tmp_path / "after.zip"
    with zipfile.ZipFile(before, "w") as archive:
        archive.writestr("keep.txt", b"untouched")
        archive.writestr("target.txt", b"original")
    with zipfile.ZipFile(after, "w") as archive:
        archive.writestr("keep.txt", b"CORRUPTED")
        if operation != "delete":
            content = b"modified payload\n" if operation == "modify" else b"original"
            archive.writestr("target.txt", content)
        if operation == "add":
            archive.writestr("added.txt", b"added payload\n")
    with pytest.raises(ValueError, match="payload"):
        simulator.validate_modification(before, after, operation)


def test_native_controls_preserve_baseline_and_record_real_case1(tmp_path):
    tools = simulator.discover_tools()
    if "7zip" not in tools or "winrar" not in tools:
        pytest.skip("Requires installed Windows 7-Zip and WinRAR")
    report = simulator.simulate(tmp_path, tools, ["A", "control-add", "control-modify"])
    assert all(r["status"] == "generated" for r in report["scenarios"])
    for record in report["scenarios"]:
        folder = Path(report["run_directory"])
        before = folder / record["before"]["path"]
        after = folder / record["after"]["path"]
        assert simulator.sha256(before) == record["before"]["sha256"]
        assert simulator.sha256(after) == record["after"]["sha256"]
        with zipfile.ZipFile(before) as archive:
            assert archive.read("target.txt") == b"original payload\n"
        with zipfile.ZipFile(after) as archive:
            assert archive.testzip() is None
            if record["operation"] == "modify":
                assert archive.read("target.txt") == b"modified payload\n"
            else:
                assert archive.read("added.txt") == b"added payload\n"
    control = report["scenarios"][1]
    assert control["before"]["analysis"]["is_multi_provenance"] is False
    assert control["after"]["analysis"]["cases"]["case1_mixed_fingerprints"] is True
    assert report["coverage"]["case1"] is True
    assert all(command["returncode"] == 0 for command in control["commands"])


def test_failed_native_command_is_retained_in_manifest(tmp_path):
    # A real process that cannot act as an archiver, without mocking subprocess.
    tools = {"7zip": Path(sys.executable), "winrar": Path(sys.executable)}
    report = simulator.simulate(tmp_path, tools, ["A"])
    record = report["scenarios"][0]
    assert record["status"] == "failed"
    assert record["commands"][0]["returncode"] != 0
    assert "after" not in record
    saved = json.loads((Path(report["run_directory"]) / "metadata.json").read_text())
    assert saved["scenarios"][0]["status"] == "failed"
    assert saved["coverage"]["dod_met"] is False


def test_native_shell_removal_changes_only_target_payload(tmp_path):
    tools = simulator.discover_tools()
    if "winrar" not in tools or "explorer" not in tools:
        pytest.skip("Requires WinRAR and Windows compressed-folder shell")
    report = simulator.simulate(tmp_path, tools, ["control-delete"])
    record = report["scenarios"][0]
    assert record["status"] == "generated", record
    folder = Path(report["run_directory"])
    with zipfile.ZipFile(folder / record["after"]["path"]) as archive:
        assert set(archive.namelist()) == {"keep.txt", "tieng-viet-\u1ec7.txt"}
    assert (folder / "control-delete/removed/target.txt").read_bytes() == b"original payload\n"
