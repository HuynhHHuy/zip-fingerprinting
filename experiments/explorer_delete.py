"""Prepare/finalize generated ZIPs around a separately observed Explorer Delete."""

import argparse
import ctypes
from datetime import datetime, timezone
import json
import os
import platform
from pathlib import Path
import sys
import tempfile
import time

from experiments.decompression_pipeline import ERRORS, _guard_path
from experiments.modification_evidence import MAX_BYTES, compare_delete, read_evidence
from scripts.simulate_modifications import ROOT, run_command, sha256, tool_version
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceTracker

WORKFLOW = "native-explorer-delete-v1"
SOURCES = {
    "keep.txt": b"unchanged payload\n",
    "target.txt": b"original payload\n",
    "tieng-viet-ệ.txt": b"Vietnamese survivor\n",
    "가나다.txt": b"Korean survivor\n",
}


def _environment() -> dict:
    acp = int(ctypes.windll.kernel32.GetACP()) if os.name == "nt" else None
    return {
        "os": platform.system(),
        "build": platform.version(),
        "python": platform.python_version(),
        "system_timezone": list(time.tzname),
        "ansi_code_page": acp,
        "legacy_encoding": f"cp{acp}" if acp and acp != 65001 else "utf-8",
    }


def _atomic_json(path: Path, report: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save(report: dict) -> None:
    run = Path(report["run_directory"])
    _atomic_json(run / "metadata.json", report)
    lines = [
        "# Explorer Delete experiment",
        "",
        f"Run: {report['run_id']}",
        f"Status: {report['status']}",
        f"Native Case 2: {report['native_case2']}",
        "",
        "GUI records are contemporaneous operator evidence, not cryptographic authentication.",
        "See metadata.json for raw header snapshots, deltas, commands, hashes and tracker reports.",
        "",
    ]
    if report.get("reason"):
        lines.append("Diagnostic: " + report["reason"])
    if "comparison" in report:
        lines.extend(
            [
                f"Rewrite scope: {report['comparison']['rewrite_scope']}",
                "",
                "| Survivor | Qualifying changes | All changed fields |",
                "| --- | --- | --- |",
            ]
        )
        for row in report["comparison"]["entries"]:
            cells = [
                row["path"],
                ", ".join(row["qualifying_changes"]) or "none",
                ", ".join(row["changes"]) or "none",
            ]
            lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    lines.extend(
        [
            "",
            "No full historical reproduction claimed. Negative/partial results remain visible.",
            "Offset/CRC/size/timestamp-only changes do not prove structural Case 2.",
            "A tracker flag alone does not establish native Case 2; both reports are retained.",
        ]
    )
    (run / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _tracker(path: Path) -> dict:
    with ZipBinaryParser(path) as parser:
        archive = parser.parse()
    return ProvenanceTracker(archive).analyze().to_dict()


def prepare(
    output: Path, executable: Path, configuration: str = "default", creation_mode: str = "cli"
) -> dict:
    if configuration not in {"default", "unicode-path"}:
        raise ValueError("Unknown configuration")
    if creation_mode not in {"cli", "gui"}:
        raise ValueError("Unknown creation mode")
    output = _guard_path(output)
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-case2-", dir=output))
    report: dict = {
        "schema_version": 1,
        "workflow": WORKFLOW,
        "run_id": run.name,
        "run_directory": str(run),
        "created_utc": _utc(),
        "status": "preparing",
        "configuration": configuration,
        "creation_mode": creation_mode,
        "native_case2": False,
        "commands": [],
        "environment": _environment(),
        "target": "target.txt",
    }
    _save(report)
    try:
        if report["environment"]["os"] != "Windows":
            report.update(status="skipped", reason="Requires native Windows Explorer")
            _save(report)
            return report
        executable = _guard_path(executable)
        if not executable.is_file():
            raise ValueError("Invalid Bandizip executable")
        report["tool"] = {
            "application": "Bandizip",
            "executable": str(executable),
            "version": tool_version(executable),
            "sha256": sha256(executable),
        }
        report["tool"]["configuration_files"] = {
            p.name: {"sha256": sha256(p), "raw_hex": p.read_bytes().hex()}
            for p in executable.parent.glob("*.ini")
            if p.stat().st_size <= 1024 * 1024
        }
        source = run / "source"
        source.mkdir()
        report["source_manifest"] = {}
        for name, content in SOURCES.items():
            path = source / name
            path.write_bytes(content)
            os.utime(path, ns=(1610364659123456700, 1610364659123456700))
            report["source_manifest"][name] = {"size": len(content), "sha256": sha256(path)}
        _save(report)
        if creation_mode == "gui":
            report.update(status="awaiting_creation", creation_ready_utc=_utc())
            _save(report)
            return report
        before = run / "before.zip"
        run_command([str(executable), "c", "-y", str(before), *SOURCES], source, report["commands"])
        _seal_baseline(run, report)
    except ERRORS as exc:
        report.update(status="failed", reason=str(exc))
    _save(report)
    return report


def _check_source(run: Path, report: dict) -> None:
    if set(report["source_manifest"]) != set(SOURCES):
        raise ValueError("Source manifest inventory changed")
    for name, row in report["source_manifest"].items():
        source = _guard_path(run / "source" / name)
        source.relative_to(run / "source")
        if source.stat().st_size != row["size"] or sha256(source) != row["sha256"]:
            raise ValueError("Anchored source payload changed")


def _seal_baseline(run: Path, report: dict) -> None:
    _check_source(run, report)
    before, after = [_guard_path(run / name) for name in ("before.zip", "after.zip")]
    baseline = read_evidence(before, report["environment"]["legacy_encoding"])
    if set(baseline["entries"]) != set(SOURCES):
        raise ValueError("Baseline inventory differs from source")
    for name, row in report["source_manifest"].items():
        entry = baseline["entries"][name]
        if row["sha256"] != entry["payload_sha256"] or row["size"] != entry["size"]:
            raise ValueError("Baseline payload differs from source")
    with before.open("rb") as original:
        data = original.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Baseline exceeds size limit while sealing")
    with after.open("xb") as stream:
        stream.write(data)
    if sha256(before) != baseline["sha256"] or sha256(after) != baseline["sha256"]:
        raise ValueError("Baseline changed while sealing; close archiver first")
    report.update(before=baseline, tracker_before=_tracker(before))
    report.update(status="awaiting_gui", prepared_utc=_utc())


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("GUI time must be an ISO string")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("GUI time must include timezone")
    return stamp


def _gui_evidence(run: Path, report: dict, path: Path, creation: bool = False) -> tuple[dict, bool]:
    path = _guard_path(path)
    path.relative_to(run)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("GUI log exceeds size limit")
    log = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(log, dict):
        raise ValueError("GUI log must be an object")
    expected = {
        "run_id": report["run_id"],
        "archive": str(run / ("before.zip" if creation else "after.zip")),
        "action": "Create" if creation else "Delete",
        "application": Path(report["tool"]["executable"]).name if creation else "explorer.exe",
    }
    if creation:
        expected.update(
            source_directory=str(run / "source"),
            executable=report["tool"]["executable"],
            selected_entries=sorted(SOURCES),
        )
    else:
        expected["target"] = "target.txt"
    if any(log.get(k) != v for k, v in expected.items()) or log.get("archive_closed") is not True:
        raise ValueError("Incomplete/path-mismatched GUI record")
    started, ended = _time(log["started_utc"]), _time(log["ended_utc"])
    ready = report["creation_ready_utc" if creation else "prepared_utc"]
    if not _time(ready) <= started <= ended <= datetime.now(timezone.utc):
        raise ValueError("GUI observation time outside experiment")
    level = log.get("evidence_level")
    if level not in {"operator_assertion", "ui_observed"}:
        raise ValueError("Unknown GUI evidence level")
    if level == "ui_observed":
        phases = set()
        for record in log.get("observations", []):
            observation_path = _guard_path(run / record["path"])
            observation_path.relative_to(run)
            if (
                observation_path.stat().st_size > MAX_BYTES
                or sha256(observation_path) != record["sha256"]
            ):
                raise ValueError("GUI observation checksum/size mismatch")
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            if not isinstance(observation, dict):
                raise ValueError("GUI observation must be an object")
            if any(
                observation.get(k) != v
                for k, v in expected.items()
                if k in {"run_id", "archive", "application", "source_directory", "executable"}
            ):
                raise ValueError("GUI observation belongs to another experiment")
            if not started <= _time(observation["observed_utc"]) <= ended:
                raise ValueError("GUI observation outside action interval")
            if not observation.get("accessibility_tree") or not observation.get("window_title"):
                raise ValueError("GUI observation lacks UI evidence")
            if observation["phase"] == "before" and (
                observation.get("selected_entries") != sorted(SOURCES)
                if creation
                else observation.get("selected_target") != "target.txt"
            ):
                raise ValueError("Wrong GUI selection")
            phases.add(observation["phase"])
        if phases != {"before", "after"}:
            raise ValueError("GUI observations require before/after evidence")
    return {
        "path": path.relative_to(run).as_posix(),
        "sha256": sha256(path),
        "record": log,
        "trust": "contemporaneous operator observations; not authenticated telemetry",
    }, level == "ui_observed"


def _load_run(run: Path, state: str) -> dict:
    metadata = _guard_path(run / "metadata.json")
    if metadata.stat().st_size > MAX_BYTES:
        raise ValueError("Metadata exceeds size limit")
    report = json.loads(metadata.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Run metadata must be an object")
    if (
        report.get("workflow") != WORKFLOW
        or report.get("schema_version") != 1
        or report.get("run_directory") != str(run)
        or report.get("run_id") != run.name
        or not run.name.startswith("run-case2-")
    ):
        raise ValueError("Not a workflow-owned run")
    if report.get("status") != state:
        raise ValueError("Cannot process this state")
    return report


def seal_creation(run: Path, gui_log: Path) -> dict:
    run = _guard_path(run)
    report = _load_run(run, "awaiting_creation")
    try:
        if report.get("creation_mode") != "gui":
            raise ValueError("Not a GUI creation run")
        report["creation_evidence"], _ = _gui_evidence(run, report, gui_log, creation=True)
        executable = _guard_path(Path(report["tool"]["executable"]))
        if sha256(executable) != report["tool"]["sha256"]:
            raise ValueError("Creation executable changed")
        report["tool"]["configuration_files_after_creation"] = {
            p.name: {"sha256": sha256(p), "raw_hex": p.read_bytes().hex()}
            for p in executable.parent.glob("*.ini")
            if p.stat().st_size <= 1024 * 1024
        }
        _seal_baseline(run, report)
    except (*ERRORS, KeyError, TypeError) as exc:
        report.update(status="failed", reason=str(exc), native_case2=False)
    _save(report)
    return report


def finalize(run: Path, gui_log: Path) -> dict:
    run = _guard_path(run)
    report = _load_run(run, "awaiting_gui")
    try:
        report["gui_evidence"], verified = _gui_evidence(run, report, gui_log)
        if report.get("creation_mode", "cli") == "gui":
            anchored = report["creation_evidence"]
            evidence, creation_verified = _gui_evidence(
                run, report, run / anchored["path"], creation=True
            )
            if evidence["sha256"] != anchored["sha256"]:
                raise ValueError("Creation evidence changed after sealing")
            verified = verified and creation_verified
        before, after = [_guard_path(run / name) for name in ("before.zip", "after.zip")]
        encoding = report["environment"]["legacy_encoding"]
        baseline = read_evidence(before, encoding)
        if baseline["sha256"] != report["before"]["sha256"]:
            raise ValueError("Baseline changed")
        _check_source(run, report)
        measured = read_evidence(after, encoding)
        frozen = _guard_path(run / "observed-after.zip")
        if frozen.exists():
            raise ValueError("Frozen archive already exists")
        data = after.read_bytes()
        if len(data) > MAX_BYTES:
            raise ValueError("Archive exceeds size limit")
        with frozen.open("xb") as stream:
            stream.write(data)
        snapshot = read_evidence(frozen, encoding)
        if snapshot["sha256"] != measured["sha256"] or sha256(after) != measured["sha256"]:
            raise ValueError("Archive changed while freezing; close Explorer writes first")
        comparison = compare_delete(baseline, snapshot)
        report.update(
            after=snapshot,
            comparison=comparison,
            tracker_after=_tracker(frozen),
            native_case2=bool(verified and comparison["global_rewrite"]),
            finalized_utc=_utc(),
        )
        report["tracker_agrees"] = (
            report["tracker_after"]["cases"]["case2_cascade_rewrite"]
            == comparison["global_rewrite"]
        )
        report["status"] = "finalized_positive" if report["native_case2"] else "finalized_negative"
    except (*ERRORS, KeyError, TypeError) as exc:
        report.update(status="failed", reason=str(exc), native_case2=False)
    _save(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--bandizip", type=Path, required=True)
    prep.add_argument("--output", type=Path, default=ROOT / "data/modified_samples")
    prep.add_argument("--configuration", choices=("default", "unicode-path"), default="default")
    prep.add_argument("--creation-mode", choices=("cli", "gui"), default="cli")
    seal = commands.add_parser("seal-creation")
    seal.add_argument("run", type=Path)
    seal.add_argument("--gui-log", type=Path, required=True)
    final = commands.add_parser("finalize")
    final.add_argument("run", type=Path)
    final.add_argument("--gui-log", type=Path, required=True)
    final.add_argument("--require-case2", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            report = prepare(args.output, args.bandizip, args.configuration, args.creation_mode)
        elif args.command == "seal-creation":
            report = seal_creation(args.run, args.gui_log)
        else:
            report = finalize(args.run, args.gui_log)
    except (*ERRORS, KeyError, TypeError) as exc:
        sys.stderr.write(f"Experiment error: {exc}\n")
        return 1
    print(
        json.dumps(
            {
                "run": report["run_directory"],
                "status": report["status"],
                "native_case2": report["native_case2"],
            }
        )
    )
    if report["status"] == "failed":
        return 1
    if report["status"] in {"preparing", "awaiting_creation", "awaiting_gui", "skipped"}:
        return 2
    return 2 if args.require_case2 and not report["native_case2"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
