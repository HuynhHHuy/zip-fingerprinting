"""Workflow/fault contracts; mocked preparation is never native evidence."""

import json
import io
from datetime import datetime, timezone
import os
from pathlib import Path
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
    # CI's Python can be a symlink, which the real executable guard rejects.
    # The mocked process needs only a private regular file, never an interpreter.
    executable = tmp_path / "Bandizip.exe"
    executable.write_bytes(b"SYNTHETIC TEST TOOL ONLY")
    return workflow.prepare(tmp_path, executable)


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


def test_mocked_archiver_is_private_regular_file(prepared, tmp_path):
    executable = Path(prepared["tool"]["executable"])
    assert executable.parent == tmp_path
    assert executable.is_file() and not executable.is_symlink()


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


def test_null_gui_timestamp_is_persisted_as_failure(prepared):
    remove_target(prepared)
    path = gui_log(prepared)
    log = json.loads(path.read_text())
    log["started_utc"] = None
    path.write_text(json.dumps(log))
    result = workflow.finalize(path.parent, path)
    assert result["status"] == "failed"
    assert result["reason"]


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
    result = workflow.prepare(tmp_path, Path(prepared["tool"]["executable"]))
    assert result["status"] == "failed"
    assert result["commands"][0]["error"]
    assert json.loads(Path(result["run_directory"], "metadata.json").read_text())["reason"]


def test_gui_log_outside_run_is_rejected(prepared, tmp_path):
    remove_target(prepared)
    outside = tmp_path / "external-log.json"
    outside.write_bytes(gui_log(prepared).read_bytes())
    assert workflow.finalize(Path(prepared["run_directory"]), outside)["status"] == "failed"


def test_configuration_snapshot_is_lossless(prepared, tmp_path):
    executable = tmp_path / "Bandizip.exe"
    executable.write_bytes(b"TEST ONLY")
    raw = "[setting]\nbZipUnicode=0\n".encode("utf-16")
    (tmp_path / "Bandizip.ini").write_bytes(raw)
    result = workflow.prepare(tmp_path, executable)
    snapshot = result["tool"]["configuration_files"]["Bandizip.ini"]
    assert bytes.fromhex(snapshot["raw_hex"]) == raw


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


@pytest.fixture
def gui_prepared(prepared, tmp_path):
    return workflow.prepare(tmp_path, Path(prepared["tool"]["executable"]), creation_mode="gui")


def create_baseline(report):
    run = Path(report["run_directory"])
    with zipfile.ZipFile(run / "before.zip", "w") as archive:
        for name in workflow.SOURCES:
            archive.write(run / "source" / name, name)


def creation_log(report, level="ui_observed"):
    """Synthetic observations exercise contracts only, never native evidence."""
    run = Path(report["run_directory"])
    log = {
        "run_id": report["run_id"],
        "archive": str(run / "before.zip"),
        "source_directory": str(run / "source"),
        "selected_entries": sorted(workflow.SOURCES),
        "executable": report["tool"]["executable"],
        "application": Path(report["tool"]["executable"]).name,
        "action": "Create",
        "started_utc": report["creation_ready_utc"],
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "archive_closed": True,
        "evidence_level": level,
        "observations": [],
    }
    for phase in ("before", "after"):
        observation = {
            **log,
            "phase": phase,
            "observed_utc": log["started_utc"],
            "window_title": "TEST ONLY Bandizip",
            "accessibility_tree": "SYNTHETIC TEST DATA ONLY",
        }
        path = run / f"creation-{phase}.json"
        path.write_text(json.dumps(observation))
        log["observations"].append({"path": path.name, "sha256": workflow.sha256(path)})
    path = run / "creation-log.json"
    path.write_text(json.dumps(log))
    return path


def test_gui_prepare_waits_without_compression(gui_prepared):
    assert gui_prepared["status"] == "awaiting_creation"
    run = Path(gui_prepared["run_directory"])
    assert (run / "source/keep.txt").is_file()
    assert not (run / "before.zip").exists()
    assert not (run / "after.zip").exists()
    assert gui_prepared["commands"] == []


def test_gui_seal_valid_baseline_and_legacy_finalize(gui_prepared):
    create_baseline(gui_prepared)
    run = Path(gui_prepared["run_directory"])
    result = workflow.seal_creation(run, creation_log(gui_prepared))
    assert result["status"] == "awaiting_gui", result
    assert result["before"]["sha256"] == workflow.sha256(run / "after.zip")
    with pytest.raises(ValueError, match="state"):
        workflow.seal_creation(run, run / "creation-log.json")
    remove_target(result)
    finalized = workflow.finalize(run, gui_log(result))
    assert finalized["status"] == "finalized_negative"


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "corrupt",
        "payload",
        "source",
        "log-path",
        "tool",
        "time",
        "selection",
        "observation",
        "after-exists",
    ],
)
def test_gui_seal_preserves_failures(gui_prepared, fault):
    create_baseline(gui_prepared)
    run = Path(gui_prepared["run_directory"])
    path = creation_log(gui_prepared)
    log = json.loads(path.read_text())
    if fault == "missing":
        (run / "before.zip").unlink()
    elif fault == "corrupt":
        (run / "before.zip").write_bytes(b"bad")
    elif fault == "payload":
        with zipfile.ZipFile(run / "before.zip", "w") as archive:
            archive.writestr("wrong", b"bad")
    elif fault == "source":
        (run / "source/keep.txt").write_bytes(b"changed")
    elif fault == "log-path":
        log["archive"] = str(run / "other.zip")
    elif fault == "tool":
        log["executable"] = "other.exe"
    elif fault == "time":
        log["started_utc"] = None
    elif fault == "selection":
        log["selected_entries"] = ["keep.txt"]
    elif fault == "observation":
        log["observations"] = []
    elif fault == "after-exists":
        (run / "after.zip").write_bytes(b"preserve me")
    path.write_text(json.dumps(log))
    result = workflow.seal_creation(run, path)
    assert result["status"] == "failed"
    assert json.loads((run / "metadata.json").read_text())["reason"]
    if fault == "after-exists":
        assert (run / "after.zip").read_bytes() == b"preserve me"


def test_finalize_revalidates_gui_creation_anchors(gui_prepared):
    create_baseline(gui_prepared)
    run = Path(gui_prepared["run_directory"])
    path = creation_log(gui_prepared)
    result = workflow.seal_creation(run, path)
    remove_target(result)
    path.write_text("{}")
    result = workflow.finalize(run, gui_log(result))
    assert result["status"] == "failed"


@pytest.mark.parametrize("level, expected", [("operator_assertion", False), ("ui_observed", True)])
def test_case2_requires_both_gui_operations(gui_prepared, level, expected):
    """Synthetic all-survivor rewrite tests evidence gating, not native Case2."""
    create_baseline(gui_prepared)
    run = Path(gui_prepared["run_directory"])
    sealed = workflow.seal_creation(run, creation_log(gui_prepared, level))
    with zipfile.ZipFile(run / "after.zip", "w") as archive:
        for name, payload in workflow.SOURCES.items():
            if name != "target.txt":
                info = zipfile.ZipInfo(name)
                old_host = sealed["before"]["entries"][name]["CDH"]["version_made_by"] >> 8
                info.create_system = 0 if old_host == 3 else 3
                archive.writestr(info, payload)
    path = gui_log(sealed, "ui_observed")
    log = json.loads(path.read_text())
    for phase in ("before", "after"):
        observation = {
            **log,
            "phase": phase,
            "observed_utc": log["started_utc"],
            "window_title": "TEST ONLY Explorer",
            "accessibility_tree": "TEST ONLY",
            "selected_target": "target.txt",
        }
        output = run / f"delete-{phase}.json"
        output.write_text(json.dumps(observation))
        log["observations"].append({"path": output.name, "sha256": workflow.sha256(output)})
    path.write_text(json.dumps(log))
    result = workflow.finalize(run, path)
    assert result["comparison"]["global_rewrite"] is True
    assert result["native_case2"] is expected


def test_gui_cli_pending_exit_codes(prepared, tmp_path, capsys):
    code = workflow.main(
        [
            "prepare",
            "--creation-mode",
            "gui",
            "--bandizip",
            prepared["tool"]["executable"],
            "--output",
            str(tmp_path),
        ]
    )
    assert code == 2
    report = json.loads(capsys.readouterr().out)
    run = Path(report["run"])
    metadata = json.loads((run / "metadata.json").read_text())
    assert metadata["status"] == "awaiting_creation"
    create_baseline(metadata)
    log = creation_log(metadata)
    assert workflow.main(["seal-creation", str(run), "--gui-log", str(log)]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "awaiting_gui"


def test_legacy_cli_metadata_without_creation_mode(prepared):
    run = Path(prepared["run_directory"])
    prepared.pop("creation_mode", None)
    workflow._atomic_json(run / "metadata.json", prepared)
    remove_target(prepared)
    result = workflow.finalize(run, gui_log(prepared))
    assert result["status"] == "finalized_negative"


def test_sealing_rejects_baseline_growth_before_copy(gui_prepared, monkeypatch):
    create_baseline(gui_prepared)
    run = Path(gui_prepared["run_directory"])
    path = creation_log(gui_prepared)
    baseline = workflow.read_evidence(run / "before.zip", "utf-8")
    monkeypatch.setattr(workflow, "read_evidence", lambda *args: baseline)
    original_open = Path.open

    def grows(file, mode="r", *args, **kwargs):
        if file == run / "before.zip" and mode == "rb":
            return io.BytesIO(b"x" * (workflow.MAX_BYTES + 1))
        return original_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", grows)
    result = workflow.seal_creation(run, path)
    assert result["status"] == "failed"
    assert not (run / "after.zip").exists()
