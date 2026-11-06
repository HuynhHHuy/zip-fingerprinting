"""Generate native before/after ZIP pairs for PH4-PROV-002 (Section 4.2).

Run from any directory with an installed package, or directly from a source checkout.
No archive headers are fabricated and no archiver is silently substituted.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zip_fingerprint.parser import ZipBinaryParser  # noqa: E402
from zip_fingerprint.provenance import ProvenanceTracker  # noqa: E402
from zip_fingerprint.exceptions import ZipFingerprintError  # noqa: E402

# creator, modifier, operation, disable baseline timestamps, expected research case
SCENARIOS = {
    "A": ("7zip", "winrar", "add", False, "case1"),
    "B": ("bandizip", "explorer", "delete", False, "case2"),
    "C": ("winzip", "7zip", "modify", False, "case1"),
    "control-add": ("7zip", "winrar", "add", True, "case1"),
    "control-modify": ("7zip", "winrar", "modify", True, "case1"),
    "control-delete": ("winrar", "explorer", "delete", False, "case2"),
}
EXECUTABLES = {
    "7zip": ("7z.exe", "7-Zip/7z.exe"),
    "winrar": ("WinRAR.exe", "WinRAR/WinRAR.exe"),
    "bandizip": ("bz.exe", "Bandizip/bz.exe"),
    "winzip": ("wzzip.exe", "WinZip/wzzip.exe"),
}


def discover_tools() -> dict[str, Path]:
    """Find Windows archivers in PATH and standard installation directories."""
    if os.name != "nt":
        return {}
    tools = {}
    for name, (executable, relative) in EXECUTABLES.items():
        candidates = [shutil.which(executable)]
        candidates.extend(
            str(Path(os.environ[folder]) / relative)
            for folder in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")
            if folder in os.environ
        )
        if name == "bandizip":
            # Older Bandizip versions shipped a console executable named bc.exe.
            candidates += [shutil.which("bc.exe")]
            candidates += [str(Path(p).with_name("bc.exe")) for p in candidates if p]
        match = next((Path(p).resolve() for p in candidates if p and Path(p).is_file()), None)
        if match:
            tools[name] = match
    shell = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/zipfldr.dll"
    if shell.is_file() and shutil.which("powershell.exe"):
        tools["explorer"] = shell
    return tools


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_version(path: Path) -> str:
    """Read the Windows product version without launching an archiver's GUI."""
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Item -LiteralPath $env:ZIP_PROV_TOOL).VersionInfo.ProductVersion",
        ],
        env={**os.environ, "ZIP_PROV_TOOL": str(path)},
        capture_output=True,
        text=True,
        errors="replace",
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"Cannot read tool version: {path}")
    return result.stdout.strip()


def run_command(args: list[str], cwd: Path, commands: list[dict]) -> None:
    """Keep command evidence even on nonzero exit or timeout."""
    record = {"argv": [str(arg) for arg in args], "cwd": str(cwd), "returncode": None}
    commands.append(record)
    try:
        result = subprocess.run(
            record["argv"],
            cwd=cwd,
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


def archive_command(
    tool: str, executable: Path, archive: Path, files: list[str], no_times: bool = False
) -> list[str]:
    if tool == "7zip":
        flags = ["-mtc=off", "-mta=off", "-mtm=off"] if no_times else []
        return [str(executable), "a", "-tzip", "-y", *flags, str(archive), *files]
    if tool == "winrar":
        return [
            str(executable),
            "a",
            "-afzip",
            "-cfg-",
            "-inul",
            "-ibck",
            "-y",
            str(archive),
            *files,
        ]
    if tool == "bandizip":
        return [str(executable), "c", "-y", str(archive), *files]
    if tool == "winzip":
        return [str(executable), "-a", str(archive), *files]
    raise ValueError(f"Unsupported archiver: {tool}")


def payloads(path: Path) -> dict[str, bytes]:
    """Read only our tiny generated fixtures, independently of the forensic parser."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate payload names")
        return {name: archive.read(name) for name in names}


def validate_modification(before: Path, after: Path, operation: str) -> None:
    original = payloads(before)
    expected = dict(original)
    if operation == "add":
        expected["added.txt"] = b"added payload\n"
    elif operation == "modify":
        expected["target.txt"] = b"modified payload\n"
    elif operation == "delete":
        del expected["target.txt"]
    else:
        raise ValueError(f"Unsupported operation: {operation}")
    if payloads(after) != expected:
        raise ValueError(f"Unexpected payload changes during {operation}")


def analyze_sample(path: Path, run_dir: Path) -> dict:
    analysis = ProvenanceTracker(ZipBinaryParser(path).parse()).analyze().to_dict()
    return {
        "path": path.relative_to(run_dir).as_posix(),
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
        "analysis": analysis,
    }


def header_changes(before: Path, after: Path) -> list[str]:
    """Compare untouched entries' raw extra fields, independently of case predictions."""

    def signatures(path):
        archive = ZipBinaryParser(path).parse()
        local = {header.offset: header for header in archive.local_file_headers}
        return {
            header.file_name: (
                header.version_made_by,
                [
                    (block.header_id, block.raw_data)
                    for block in local[header.local_header_offset].extra_fields
                ],
                [(block.header_id, block.raw_data) for block in header.extra_fields],
            )
            for header in archive.central_directory_headers
        }

    old, new = signatures(before), signatures(after)
    return sorted(
        name for name in old.keys() & new.keys() if name != "target.txt" and old[name] != new[name]
    )


def simulate(output: Path, tools: dict[str, Path], selected: list[str]) -> dict:
    unknown = set(selected) - SCENARIOS.keys()
    if unknown:
        raise ValueError(f"Unknown scenarios: {sorted(unknown)}")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    report = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "run_directory": str(run_dir),
        "tools": {},
        "scenarios": [],
        "coverage": {},
        "shell_removal_method": "Shell.Application MoveHere (not Explorer Delete UI)",
    }
    for name, path in tools.items():
        try:
            report["tools"][name] = {"path": str(path), "version": tool_version(path)}
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            report["tools"][name] = {"path": str(path), "version_error": str(exc)}
    for scenario in selected:
        creator, modifier, operation, no_times, expected = SCENARIOS[scenario]
        record = {
            "id": scenario,
            "creator": creator,
            "modifier": modifier,
            "operation": operation,
            "expected_case": expected,
            "baseline_timestamps_disabled": no_times,
            "commands": [],
        }
        report["scenarios"].append(record)
        missing = [name for name in (creator, modifier) if name not in tools]
        if missing:
            record.update(status="skipped", reason="Missing tools: " + ", ".join(missing))
            continue
        work = run_dir / scenario
        work.mkdir()
        source = work / "source"
        source.mkdir()
        before, after = work / "before.zip", work / "after.zip"
        files = {
            "keep.txt": b"unchanged payload\n",
            "target.txt": b"original payload\n",
            "tieng-viet-\u1ec7.txt": b"unicode payload\n",
        }
        for name, content in files.items():
            path = source / name
            path.write_bytes(content)
            os.utime(path, ns=(1610364659123456700, 1610364659123456700))
        try:
            run_command(
                archive_command(creator, tools[creator], before, list(files), no_times),
                source,
                record["commands"],
            )
            if payloads(before) != files:
                raise ValueError("Baseline payload differs from source")
            record["before"] = analyze_sample(before, run_dir)
            shutil.copyfile(before, after)
            if operation == "delete":
                destination = work / "removed"
                destination.mkdir()
                run_command(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(ROOT / "scripts" / "remove_zip_entry_shell.ps1"),
                        "-Archive",
                        str(after),
                        "-Destination",
                        str(destination),
                        "-Entry",
                        "target.txt",
                    ],
                    source,
                    record["commands"],
                )
            else:
                target = "added.txt" if operation == "add" else "target.txt"
                content = b"added payload\n" if operation == "add" else b"modified payload\n"
                (source / target).write_bytes(content)
                # A newer timestamp also exercises update-oriented archivers reliably.
                os.utime(source / target, ns=(1641900659123456700, 1641900659123456700))
                run_command(
                    archive_command(modifier, tools[modifier], after, [target]),
                    source,
                    record["commands"],
                )
            validate_modification(before, after, operation)
            if sha256(before) != record["before"]["sha256"]:
                raise ValueError("Baseline was modified")
            record["after"] = analyze_sample(after, run_dir)
            record["untouched_entries_with_header_changes"] = header_changes(before, after)
            record.update(status="generated", payload_validation="passed")
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, ZipFingerprintError) as exc:
            record.update(status="failed", reason=str(exc))
    generated = [r for r in report["scenarios"] if r["status"] == "generated"]
    case1 = any(r["after"]["analysis"]["cases"]["case1_mixed_fingerprints"] for r in generated)
    case2 = any(r["after"]["analysis"]["cases"]["case2_cascade_rewrite"] for r in generated)
    report["coverage"] = {
        "case1": case1,
        "case2": case2,
        "dod_met": len(generated) >= 2 and case1 and case2,
    }
    (run_dir / "metadata.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "data/modified_samples")
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIOS,
        help="Repeat to select scenarios; default: all, including controls",
    )
    for tool in EXECUTABLES:
        parser.add_argument(f"--{tool}", type=Path, help="Override installed console executable")
    parser.add_argument(
        "--require-cases",
        action="store_true",
        help="Exit 2 unless generated samples cover both Case 1 and Case 2",
    )
    args = parser.parse_args()
    tools = discover_tools()
    for name in EXECUTABLES:
        override = getattr(args, name)
        if override:
            if not override.is_file():
                parser.error(f"Not an executable file: {override}")
            tools[name] = override.resolve()
    report = simulate(args.output, tools, args.scenario or list(SCENARIOS))
    for record in report["scenarios"]:
        print(
            f"{record['id']}: {record['status']}"
            + (f" ({record['reason']})" if "reason" in record else "")
        )
    print("Metadata:", Path(report["run_directory"]) / "metadata.json")
    print("Case coverage:", json.dumps(report["coverage"]))
    if any(r["status"] == "failed" for r in report["scenarios"]):
        return 1
    if not any(r["status"] == "generated" for r in report["scenarios"]):
        return 2
    return 2 if args.require_cases and not report["coverage"]["dod_met"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
