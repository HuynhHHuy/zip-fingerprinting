"""Pre-registered SW2 screening for Case 2 (#19, PH4-PROV-002).

The six cells, commands, criteria and stopping rule are fixed in
docs/research/sw2-screening-preregistration.md (commit 8c4975d). This module only
runs those cells; it has no option to add a cell or change a command.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from experiments.decompression_pipeline import ERRORS, _guard_path
from experiments.explorer_delete import SOURCES, _atomic_json, _environment, _tracker
from experiments.modification_evidence import compare_survivors, read_evidence
from scripts.simulate_modifications import (
    ROOT,
    archive_command,
    discover_tools as discover_installed,
    sha256,
    tool_version,
)

WORKFLOW = "sw2-screening-v1"
PREREGISTRATION = "8c4975de7415ddd524beac189dad5e752da81668"
# cell: (SW1 creator, SW2 modifier, operation)
CELLS = {
    "S1": ("bandizip", "7zip", "delete"),
    "S2": ("bandizip", "winrar", "delete"),
    "S3": ("bandizip", "powershell5", "add"),
    "S4": ("bandizip", "pwsh7", "add"),
    "S5": ("bandizip", "shell", "add"),
    "S6": ("7zip", "bandizip", "delete"),
}
TARGET = "target.txt"
ADDED_NAME = "added.txt"
ADDED_PAYLOAD = b"added payload\n"
SOURCE_TIME_NS = 1610364659123456700
ADDED_TIME_NS = 1641900659123456700
COMPRESS = (
    "$ErrorActionPreference = 'Stop'; "
    "Compress-Archive -LiteralPath $env:ZIP_PROV_ADD "
    "-DestinationPath $env:ZIP_PROV_ARCHIVE -Update"
)


def discover_tools(bandizip: Path | None) -> dict[str, Path]:
    """Installed 7-Zip/WinRAR/shell, both PowerShells, and an explicit Bandizip."""
    found = discover_installed()
    tools: dict[str, Path] = {n: found[n] for n in ("7zip", "winrar") if n in found}
    if "explorer" in found:
        tools["shell"] = found["explorer"]
    system = Path(os.environ.get("SystemRoot", "C:/Windows"))
    legacy = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
    if os.name == "nt" and legacy.is_file():
        tools["powershell5"] = legacy
    candidates = [shutil.which("pwsh.exe")]
    if "ProgramFiles" in os.environ:
        candidates.append(str(Path(os.environ["ProgramFiles"]) / "PowerShell/7/pwsh.exe"))
    pwsh = next((Path(p) for p in candidates if p and Path(p).is_file()), None)
    if os.name == "nt" and pwsh:
        tools["pwsh7"] = pwsh
    if bandizip is not None:
        bandizip = _guard_path(bandizip)
        if not bandizip.is_file():
            raise ValueError(f"Not an executable file: {bandizip}")
        tools["bandizip"] = bandizip
    return tools


def sw2_command(
    tool: str, executable: Path, archive: Path, added: Path
) -> tuple[list[str], dict[str, str]]:
    """The pre-registered SW2 argv, plus environment values it reads."""
    if tool == "7zip":
        return [str(executable), "d", "-tzip", str(archive), TARGET], {}
    if tool == "winrar":
        return [str(executable), "d", "-ibck", "-inul", "-y", str(archive), TARGET], {}
    if tool == "bandizip":
        return [str(executable), "d", "-y", str(archive), TARGET], {}
    if tool in ("powershell5", "pwsh7"):
        env = {"ZIP_PROV_ADD": str(added), "ZIP_PROV_ARCHIVE": str(archive)}
        return [str(executable), "-NoProfile", "-NonInteractive", "-Command", COMPRESS], env
    if tool == "shell":
        script = ROOT / "scripts" / "add_zip_entry_shell.ps1"
        argv = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Archive",
            str(archive),
            "-Source",
            str(added),
        ]
        return argv, {}
    raise ValueError(f"Unsupported SW2: {tool}")


def describe_tool(path: Path) -> dict:
    row: dict = {"path": str(path), "sha256": sha256(path)}
    try:
        row["version"] = tool_version(path)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        row["version_error"] = str(exc)
    row["signature"] = _signature(path)
    return row


def _signature(path: Path) -> str:
    if os.name != "nt":
        return "unavailable"
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$s = Get-AuthenticodeSignature -LiteralPath $env:ZIP_PROV_TOOL; "
                '"$($s.Status) | $($s.SignerCertificate.Subject)"',
            ],
            env={**os.environ, "ZIP_PROV_TOOL": str(path)},
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"error: {exc}"
    return result.stdout.strip() or f"error: exit {result.returncode}"


def _run(args: list[str], cwd: Path, commands: list[dict], env: dict[str, str]) -> None:
    """Like simulate_modifications.run_command, with recorded extra environment."""
    record: dict = {"argv": [str(a) for a in args], "cwd": str(cwd), "env": env}
    record["returncode"] = None
    commands.append(record)
    try:
        result = subprocess.run(
            record["argv"],
            cwd=cwd,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        record["error"] = str(exc)
        raise RuntimeError(str(exc)) from exc
    record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"Native command failed ({result.returncode}): {args[0]}")


def run_cell(work: Path, sw1: str, sw2: str, operation: str, tools: dict[str, Path]) -> dict:
    """SW1 creates before.zip, SW2 modifies a copy; nothing else touches either."""
    cell: dict = {"sw1": sw1, "sw2": sw2, "operation": operation, "commands": []}
    missing = [name for name in (sw1, sw2) if name not in tools]
    if missing:
        cell.update(status="skipped", reason="Missing tools: " + ", ".join(missing))
        return cell
    try:
        work = _guard_path(work)
        work.mkdir(parents=True)
        source, addition = work / "source", work / "addition"
        source.mkdir()
        for name, content in SOURCES.items():
            (source / name).write_bytes(content)
            os.utime(source / name, ns=(SOURCE_TIME_NS, SOURCE_TIME_NS))
        added = addition / ADDED_NAME
        if operation == "add":
            addition.mkdir()
            added.write_bytes(ADDED_PAYLOAD)
            os.utime(added, ns=(ADDED_TIME_NS, ADDED_TIME_NS))
        before, after = work / "before.zip", work / "after.zip"
        encoding = _environment()["legacy_encoding"]
        create = archive_command(sw1, tools[sw1], before, list(SOURCES))
        _run(create, source, cell["commands"], {})
        baseline = read_evidence(before, encoding)
        if set(baseline["entries"]) != set(SOURCES):
            raise ValueError("Baseline inventory differs from source")
        for name, content in SOURCES.items():
            if baseline["entries"][name]["payload_sha256"] != hashlib.sha256(content).hexdigest():
                raise ValueError(f"Baseline payload differs from source: {name}")
        shutil.copyfile(before, after)
        argv, env = sw2_command(sw2, tools[sw2], after, added)
        _run(argv, work, cell["commands"], env)
        if sha256(before) != baseline["sha256"]:
            raise ValueError("Baseline was modified")
        snapshot = read_evidence(after, encoding)
        if operation == "add":
            row = snapshot["entries"].get(ADDED_NAME)
            if not row or row["payload_sha256"] != hashlib.sha256(ADDED_PAYLOAD).hexdigest():
                raise ValueError("Added entry payload mismatch")
        cell["comparison"] = compare_survivors(
            baseline,
            snapshot,
            removed={TARGET} if operation == "delete" else (),
            added={ADDED_NAME} if operation == "add" else (),
        )
        cell.update(
            before=baseline,
            after=snapshot,
            tracker_before=_tracker(before),
            tracker_after=_tracker(after),
            status="generated",
        )
    except (*ERRORS, KeyError, TypeError) as exc:
        cell.update(status="failed", reason=str(exc))
        cell.pop("comparison", None)
    return cell


def _save(report: dict) -> None:
    run = Path(report["run_directory"])
    _atomic_json(run / "metadata.json", report)
    lines = [
        "# SW2 screening",
        "",
        f"Run: {report['run_id']}",
        f"Pre-registration: {PREREGISTRATION}",
    ]
    if report.get("confirmation_of"):
        lines.append(f"Confirmation of: {report['confirmation_of']}")
    lines += [
        "",
        "| Cell | SW1 -> SW2 | Operation | Status | Scope | Tracker Case 2 after |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for cell in report["cells"]:
        scope = cell.get("comparison", {}).get("rewrite_scope", "-")
        tracker = cell.get("tracker_after", {}).get("cases", {}).get("case2_cascade_rewrite", "-")
        lines.append(
            f"| {cell['id']} | {cell['sw1']} -> {cell['sw2']} | {cell['operation']} | "
            f"{cell['status']} | {scope} | {tracker} |"
        )
    for cell in report["cells"]:
        if "comparison" in cell:
            lines += ["", f"## {cell['id']}", ""]
            for row in cell["comparison"]["entries"]:
                qualifying = ", ".join(row["qualifying_changes"]) or "none"
                lines.append(f"- {row['path']}: {qualifying}")
        elif cell.get("reason"):
            lines += ["", f"## {cell['id']}", "", f"{cell['status']}: {cell['reason']}"]
    lines += [
        "",
        "Scope 'all' needs a structural change on every survivor; offset/CRC/size/time alone",
        "do not count. A tracker flag alone does not establish Case 2.",
    ]
    (run / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def screen(
    output: Path,
    tools: dict[str, Path],
    cells: list[str],
    confirmation_of: str | None = None,
) -> dict:
    unknown = set(cells) - CELLS.keys()
    if unknown:
        raise ValueError(f"Unknown cells: {sorted(unknown)}")
    if confirmation_of is not None and cells != [confirmation_of]:
        raise ValueError("A confirmation runs exactly one cell")
    output = _guard_path(output)
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-sw2-", dir=output))
    report: dict = {
        "schema_version": 1,
        "workflow": WORKFLOW,
        "preregistration_commit": PREREGISTRATION,
        "run_id": run.name,
        "run_directory": str(run),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "confirmation_of": confirmation_of,
        "environment": _environment(),
        "tools": {name: describe_tool(path) for name, path in sorted(tools.items())},
        "cells": [],
    }
    _save(report)
    for cell_id in cells:
        sw1, sw2, operation = CELLS[cell_id]
        cell = {"id": cell_id, **run_cell(run / cell_id, sw1, sw2, operation, tools)}
        report["cells"].append(cell)
        _save(report)
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    _save(report)
    return report


def exit_code(report: dict, require_case2: bool) -> int:
    cells = report["cells"]
    if any(cell["status"] == "failed" for cell in cells):
        return 1
    generated = [cell for cell in cells if cell["status"] == "generated"]
    if not generated:
        return 2
    found = any(cell["comparison"]["rewrite_scope"] == "all" for cell in generated)
    return 2 if require_case2 and not found else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "confirm"):
        sub = commands.add_parser(name)
        sub.add_argument("--output", type=Path, default=ROOT / "data/modified_samples")
        sub.add_argument("--bandizip", type=Path, help="Bandizip.x64.exe of the portable build")
        sub.add_argument("--require-case2", action="store_true")
        if name == "run":
            sub.add_argument("--cell", action="append", choices=CELLS)
        else:
            sub.add_argument("--cell", required=True, choices=CELLS)
    args = parser.parse_args(argv)
    try:
        tools = discover_tools(args.bandizip)
        if args.command == "run":
            report = screen(args.output, tools, args.cell or list(CELLS))
        else:
            report = screen(args.output, tools, [args.cell], confirmation_of=args.cell)
    except ERRORS as exc:
        sys.stderr.write(f"Screening error: {exc}\n")
        return 1
    for cell in report["cells"]:
        scope = cell.get("comparison", {}).get("rewrite_scope")
        print(json.dumps({"cell": cell["id"], "status": cell["status"], "scope": scope}))
    print("Metadata:", Path(report["run_directory"]) / "metadata.json")
    return exit_code(report, args.require_case2)


if __name__ == "__main__":
    raise SystemExit(main())
