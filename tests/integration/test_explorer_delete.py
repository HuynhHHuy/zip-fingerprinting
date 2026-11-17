"""Workflow/fault contracts; mocked preparation is never native evidence."""

import json
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import subprocess
import zipfile

import pytest

from experiments import explorer_delete as workflow


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(
        workflow, "_environment", lambda: {"os": "Windows", "legacy_encoding": "utf-8"}
    )
    monkeypatch.setattr(workflow, "tool_version", lambda path: "TEST ONLY")

    def compress(args, cwd, commands):
        commands.append({"argv": args, "cwd": str(cwd), "returncode": 0})
        with zipfile.ZipFile(args[-5], "w") as z:
            for file in sorted(Path(cwd).iterdir()):
                z.write(file, file.name)

    monkeypatch.setattr(workflow, "run_command", compress)
    return workflow.prepare(tmp_path, Path(sys.executable))


def gui_log(report, level="operator_assertion"):
    run = Path(report["run_directory"])
    record = {
        "run_id": report["run_id"],
        "archive": str(run / "after.zip"),
        "target": "target.txt",
        "action": "Delete",
        "application": "explorer.exe",
        "started_utc": report["prepared_utc"],
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "archive_closed": True,
        "evidence_level": level,
        "observations": [],
    }
    path = run / "gui-log.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def remove_target(report, corrupt=False):
    run = Path(report["run_directory"])
    with zipfile.ZipFile(run / "before.zip") as z:
        files = {i.filename: z.read(i) for i in z.infolist() if i.filename != "target.txt"}
    if corrupt:
        files["keep.txt"] = b"corrupt"
    with zipfile.ZipFile(run / "after.zip", "w") as z:
        for name, data in files.items():
            z.writestr(name, data)


def test_prepare_anchors_and_distinct_runs(prepared):
    assert prepared["status"] == "awaiting_gui", prepared
    assert prepared["before"]["sha256"]
    assert len(prepared["source_manifest"]) == 4
    assert prepared["commands"][0]["returncode"] == 0
    assert prepared["native_case2"] is False


def test_operator_assertion_does_not_establish_native_case2(prepared):
    remove_target(prepared)
    report = workflow.finalize(Path(prepared["run_directory"]), gui_log(prepared))
    assert report["status"] == "finalized_negative"
    assert report["comparison"]["payload_validation"]
    assert report["native_case2"] is False
    assert Path(report["run_directory"], "report.md").exists()
    with pytest.raises(ValueError, match="state"):
        workflow.finalize(
            Path(report["run_directory"]), Path(report["run_directory"], "gui-log.json")
        )


@pytest.mark.parametrize(
    "fault", ["payload", "baseline", "source", "unchanged", "gui-path", "missing-log", "gui-list"]
)
def test_finalize_preserves_failures(prepared, fault):
    run = Path(prepared["run_directory"])
    log = gui_log(prepared)
    if fault != "unchanged":
        remove_target(prepared, corrupt=fault == "payload")
    if fault == "baseline":
        (run / "before.zip").write_bytes(b"modified")
    if fault == "source":
        (run / "source/keep.txt").write_bytes(b"modified")
    if fault == "gui-list":
        log.write_text("[]")
    if fault == "gui-path":
        record = json.loads(log.read_text())
        record["archive"] = str(run / "other.zip")
        log.write_text(json.dumps(record))
    if fault == "missing-log":
        log = run / "missing.json"
    result = workflow.finalize(run, log)
    assert result["status"] == "failed"
    saved = json.loads((run / "metadata.json").read_text())
    assert saved["reason"] and saved["native_case2"] is False


def test_claimed_ui_without_observations_is_rejected(prepared):
    remove_target(prepared)
    result = workflow.finalize(Path(prepared["run_directory"]), gui_log(prepared, "ui_observed"))
    assert result["status"] == "failed"


def test_malformed_observation_is_persisted_as_failure(prepared):
    remove_target(prepared)
    path = gui_log(prepared, "ui_observed")
    observation = path.parent / "bad-observation.json"
    observation.write_text("[]")
    log = json.loads(path.read_text())
    log["observations"] = [{"path": observation.name, "sha256": workflow.sha256(observation)}]
    path.write_text(json.dumps(log))
    result = workflow.finalize(path.parent, path)
    assert result["status"] == "failed"


def test_invalid_tool_retains_run(tmp_path):
    report = workflow.prepare(tmp_path, tmp_path / "missing.exe")
    assert report["status"] in {"failed", "skipped"}
    assert Path(report["run_directory"], "metadata.json").exists()
    second = workflow.prepare(tmp_path, tmp_path / "missing.exe")
    assert second["run_directory"] != report["run_directory"]


@pytest.mark.parametrize(
    "error", [RuntimeError("process failed"), subprocess.TimeoutExpired("tool", 60)]
)
def test_process_errors_persist_commands(prepared, monkeypatch, tmp_path, error):
    def fail(args, cwd, commands):
        commands.append({"argv": args, "cwd": str(cwd), "error": str(error)})
        raise error

    monkeypatch.setattr(workflow, "run_command", fail)
    result = workflow.prepare(tmp_path, Path(sys.executable))
    assert result["status"] == "failed"
    assert result["commands"][0]["error"]
    assert json.loads(Path(result["run_directory"], "metadata.json").read_text())["reason"]


def test_gui_log_outside_run_is_rejected(prepared, tmp_path):
    remove_target(prepared)
    outside = tmp_path / "external-log.json"
    outside.write_bytes(gui_log(prepared).read_bytes())
    assert workflow.finalize(Path(prepared["run_directory"]), outside)["status"] == "failed"


def test_ui_observations_are_retained_for_negative_result(prepared):
    """Synthetic UI records test validation, not an actual Explorer action."""
    remove_target(prepared)
    path = gui_log(prepared, "ui_observed")
    log = json.loads(path.read_text())
    for phase in ("before", "after"):
        observation = {
            "run_id": prepared["run_id"],
            "archive": log["archive"],
            "application": "explorer.exe",
            "observed_utc": log["started_utc"],
            "phase": phase,
            "window_title": "after.zip",
            "selected_target": "target.txt",
            "accessibility_tree": "SYNTHETIC TEST DATA ONLY",
        }
        output = path.parent / f"gui-{phase}.json"
        output.write_text(json.dumps(observation))
        log["observations"].append({"path": output.name, "sha256": workflow.sha256(output)})
    path.write_text(json.dumps(log))
    report = workflow.finalize(path.parent, path)
    assert report["status"] == "finalized_negative", report
    assert report["comparison"]["rewrite_scope"] == "none"
    assert report["gui_evidence"]["record"]["observations"]


def test_foreign_run_rejected(tmp_path):
    (tmp_path / "metadata.json").write_text("{}")
    with pytest.raises(ValueError):
        workflow.finalize(tmp_path, tmp_path / "gui.json")


def test_native_bandizip_prepare(tmp_path):
    executable = os.environ.get("CASE2_BANDIZIP")
    if os.name != "nt" or not executable:
        pytest.skip("Requires explicitly selected native portable Bandizip")
    report = workflow.prepare(tmp_path, Path(executable))
    assert report["status"] == "awaiting_gui", report
    assert report["tool"]["version"] != "TEST ONLY"
    assert report["before"]["entries"]["가나다.txt"]["payload_sha256"]
