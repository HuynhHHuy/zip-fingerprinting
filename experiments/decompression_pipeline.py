"""Native Windows decompression experiment orchestration (Task 3).

Only private corpus copies and self-generated archives are accepted. This is
an immediate post-process metadata snapshot, not a claim that NTFS access
times have settled. No filesystem policy or machine timezone is changed.
"""

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
import time
from typing import Any
import zipfile
import zlib

from experiments import windows_filetimes as ft
from experiments.trace_decompression import (
    FIELDS,
    ROOT,
    TIME_IDS,
    _path,
    _zone,
    analyze_observations,
    archive_references,
)
from scripts.prepare_corpus import create_standard_corpus
from scripts.simulate_modifications import run_command, sha256, tool_version
from zip_fingerprint.exceptions import ZipFingerprintError

TOOLS = ("7zip", "winrar")
PROFILES = ("ntfs", "no-extra")
SOURCE_TIMES = {
    "birth": 132232158571234567,
    "modified": 132548382591234567,
    "accessed": 132863742557654321,
}
ERRORS = (
    OSError,
    ValueError,
    RuntimeError,
    subprocess.TimeoutExpired,
    zipfile.BadZipFile,
    zlib.error,
    ZipFingerprintError,
)


def _guard_path(path: Path) -> Path:
    """Check lexical ancestors before resolve can hide junctions/reparse points."""
    target = Path(os.path.abspath(path))
    for ancestor in (target, *target.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"Refusing reparse point: {ancestor}")
    return target


def prepare_destination(destination: Path) -> None:
    destination = _guard_path(destination)
    if destination.exists():
        raise ValueError(f"Extraction destination already exists: {destination}")
    if ft.volume_info(destination.parent)["filesystem"] != "NTFS":
        raise ValueError("Extraction destination must be on NTFS")
    destination.mkdir()


def _tree_paths(root: Path) -> list[Path]:
    result = []
    for child in sorted(root.iterdir()):
        _guard_path(child)
        if not child.is_file() and not child.is_dir():
            raise ValueError(f"Unsupported filesystem entry: {child}")
        result.append(child)
        if child.is_dir():
            result.extend(_tree_paths(child))
    return result


def snapshot_tree(destination: Path) -> list[dict]:
    """Read metadata for the entire tree before anybody reads extracted payloads."""
    observations = []
    for path in _tree_paths(destination):
        started = ft.now_filetime()
        values = ft.read_bmac(path)
        observations.append(
            {
                "path": path.relative_to(destination).as_posix(),
                **values,
                "utc": {key: ft.filetime_utc(value) for key, value in values.items()},
                "observation_bounds": [started, ft.now_filetime()],
            }
        )
    return observations


def _safe_zip_name(name: str) -> str:
    key = _path(name)
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{p}{n}" for p in ("COM", "LPT") for n in range(1, 10)
    }
    if any(
        part.endswith((".", " ")) or part.split(".")[0].upper() in reserved
        for part in key.split("/")
    ):
        raise ValueError(f"Unsafe Windows ZIP path: {name!r}")
    return key


def validate_zip(
    archive: Path,
    expected: dict[str, bytes],
    directories: list[str],
    profile: str,
    dos_timezone: str,
) -> dict:
    """Validate headers and payloads in memory; never extract untrusted paths."""
    names = set()
    actual_files = {}
    with zipfile.ZipFile(archive) as stream:
        for info in stream.infolist():
            key = _safe_zip_name(info.filename)
            if key.casefold() in names:
                raise ValueError(f"Duplicate/aliased ZIP entry: {info.filename}")
            names.add(key.casefold())
            mode = stat.S_IFMT(info.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.external_attr & 0x400:
                raise ValueError(f"Unsupported ZIP link/reparse/type: {info.filename}")
            if info.flag_bits & 1:
                raise ValueError("Encrypted experiment ZIPs are unsupported")
            if not info.is_dir():
                actual_files[key] = stream.read(info)  # CRC is checked during read.
        if stream.testzip() is not None:
            raise ValueError("ZIP CRC validation failed")
    if actual_files != expected:
        raise ValueError("ZIP payload inventory/checksum differs from source")
    references = archive_references(archive, dos_timezone)
    if set(references["entries"]) != set(expected) | set(directories):
        raise ValueError("ZIP directory inventory differs from source")
    for entry in references["entries"].values():
        if any("LFH_CDH_NAME_CONFLICT" in header["issues"] for header in entry["headers"]):
            raise ValueError("ZIP LFH/CDH filename mismatch")
        for header in entry["headers"]:
            for extra in header["extra_fields"]:
                if extra["id"] == 0x7075:
                    if extra["status"] != "valid":
                        raise ValueError("Invalid Unicode Path extra field")
                    alternate = bytes.fromhex(extra["raw_hex"])[5:].decode("utf-8")
                    if _safe_zip_name(alternate) != entry["path"]:
                        raise ValueError("Unicode Path override differs from source inventory")
        ids = {extra["id"] for header in entry["headers"] for extra in header["extra_fields"]}
        if profile == "ntfs" and entry["headers"]:
            if ids & TIME_IDS != {10} or entry["context"]["status"] != "unique":
                raise ValueError("Archiver did not produce the requested NTFS timestamp profile")
            fields = {ref["field"] for ref in entry["references"] if ref["label"] == "E"}
            if fields != set(SOURCE_TIMES):
                raise ValueError("NTFS source archive lacks B/M/A references")
        elif profile == "no-extra" and ids & TIME_IDS:
            raise ValueError("Archiver did not produce the requested no-extra profile")
    return references


def validate_extracted(
    destination: Path, expected: dict[str, bytes], directories: list[str]
) -> dict:
    paths = _tree_paths(destination)
    files = {path.relative_to(destination).as_posix(): path for path in paths if path.is_file()}
    folders = {path.relative_to(destination).as_posix() for path in paths if path.is_dir()}
    if set(files) != set(expected) or folders != set(directories):
        raise ValueError("Extracted inventory differs from source")
    hashes = {}
    import hashlib

    for name, path in files.items():
        payload = path.read_bytes()
        if payload != expected[name]:
            raise ValueError(f"Extracted payload mismatch: {name}")
        hashes[name] = hashlib.sha256(payload).hexdigest()
    return {"passed": True, "files": hashes, "directories": sorted(folders)}


def _source(source: Path) -> tuple[dict[str, bytes], list[str], dict]:
    with redirect_stdout(io.StringIO()):
        create_standard_corpus(source)
    manifest_path = source / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    baseline = json.loads((ROOT / "data/templates/manifest.json").read_text(encoding="utf-8"))
    if manifest != baseline:
        raise ValueError("Private source manifest differs from DATA-001 baseline")
    expected = {}
    directories = []
    for row in manifest["entries"]:
        if row["path"] != "set1" and not row["path"].startswith("set1/"):
            continue
        path = source / row["path"]
        if row["type"] == "directory":
            directories.append(row["path"])
        else:
            if path.stat().st_size != row["size"] or sha256(path) != row["sha256"]:
                raise ValueError(f"Source payload mismatch: {row['path']}")
            expected[row["path"]] = path.read_bytes()
    ordered = sorted([*expected, *directories], key=lambda name: (-name.count("/"), name))
    for name in ordered:
        ft.set_source_times(source / name, **SOURCE_TIMES)
    observations = []
    for name in ordered:
        values = ft.read_bmac(source / name)
        if any(values[key] != value for key, value in SOURCE_TIMES.items()):
            raise ValueError(f"NTFS did not retain requested source timestamps: {name}")
        observations.append(
            {
                "path": name,
                **values,
                "utc": {key: ft.filetime_utc(value) for key, value in values.items()},
            }
        )
    return (
        expected,
        directories,
        {"manifest_sha256": sha256(manifest_path), "source_times": observations},
    )


def _environment(output: Path) -> dict:
    offset = datetime.now().astimezone().utcoffset()
    env: dict[str, Any] = {
        "os": platform.platform(),
        "build": platform.version(),
        "python": platform.python_version(),
        "system_timezone": list(time.tzname),
        "current_utc_offset_seconds": offset.total_seconds() if offset is not None else None,
        "commands": [],
        "last_access_policy": "unknown",
    }
    if os.name == "nt":
        env["volume"] = ft.volume_info(output)
        try:
            run_command(
                [
                    str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/fsutil.exe"),
                    "behavior",
                    "query",
                    "disablelastaccess",
                ],
                output,
                env["commands"],
            )
            env["last_access_policy"] = env["commands"][-1]["stdout"].strip()
        except ERRORS as exc:
            env["last_access_policy_error"] = str(exc)
    return env


def _save(report: dict) -> None:
    path = Path(report["report_path"])
    markdown = [
        "# Windows decompression run",
        "",
        f"Created UTC: {report['created_utc']}",
        f"DOS timezone: {report['dos_timezone']}",
        f"Measured: {report['coverage'].get('measured', 0)}",
        f"dod_met: {report['coverage'].get('dod_met', False)}",
        "",
        "Partial/failed runs retain their current status. See report.json for raw",
        "BMAC/UTC, commands, bounds, checksums, references and time-reversal analysis.",
        "",
        "| Item | Status | Reason |",
        "| --- | --- | --- |",
    ]
    rows = [
        *({"id": tool, **info} for tool, info in report["tools"].items()),
        *report["profiles"],
        *report["measurements"],
    ]
    for row in rows:
        cells = [row.get("id", row.get("profile", "")), row["status"], row.get("reason", "")]
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells]
        markdown.append("| " + " | ".join(cells) + " |")
    markdown.extend(["", "## Limitations", "", *report["limitations"]])
    for target, body in (
        (path, json.dumps(report, indent=2) + "\n"),
        (path.with_suffix(".md"), "\n".join(markdown) + "\n"),
    ):
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix="report-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(body)
        try:
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def _coverage(report: dict) -> dict:
    measured = [row for row in report["measurements"] if row["status"] == "measured"]
    grouped: dict[tuple, list[int]] = {}
    pairs: dict[tuple, dict] = {}
    for row in measured:
        pairs.setdefault((row["profile"], row["repeat"]), {})[row["tool"]] = row
    for (profile, repeat), tools in pairs.items():
        if set(tools) != set(TOOLS) or tools["7zip"]["zip_sha256"] != tools["winrar"]["zip_sha256"]:
            continue
        by_path = {
            tool: {entry["path"]: entry for entry in row["analysis"]["entries"]}
            for tool, row in tools.items()
        }
        for path in by_path["7zip"].keys() & by_path["winrar"].keys():
            for field in FIELDS:
                left, right = [by_path[tool][path]["bmac"][field] for tool in TOOLS]
                if (
                    left["status"] == right["status"] == "unique"
                    and left["labels"] != right["labels"]
                ):
                    key = (profile, path, field, left["labels"][0], right["labels"][0])
                    grouped.setdefault(key, []).append(repeat)
    differences = [
        {
            "profile": key[0],
            "path": key[1],
            "field": key[2],
            "labels": dict(zip(TOOLS, key[3:])),
            "repeats": sorted(repeats),
        }
        for key, repeats in sorted(grouped.items())
    ]
    required = (
        len(report["selection"]["tools"])
        * len(report["selection"]["profiles"])
        * report["selection"]["repeat"]
    )
    complete = (
        len(measured) == required
        and all(row["status"] == "generated" for row in report["profiles"])
        and all(info["status"] == "available" for info in report["tools"].values())
    )
    full_matrix = (
        set(report["selection"]["tools"]) == set(TOOLS)
        and set(report["selection"]["profiles"]) == set(PROFILES)
        and report["selection"]["repeat"] >= 3
    )
    stable = any(
        len(difference["repeats"]) == report["selection"]["repeat"] for difference in differences
    )
    return {
        "expected_measurements": required,
        "measured": len(measured),
        "complete": complete,
        "tool_differences": differences,
        "dod_met": complete and full_matrix and stable,
    }


def trace(
    output: Path,
    tools: dict[str, Path],
    dos_timezone: str,
    selected_tools: list[str] | None = None,
    profiles: list[str] | None = None,
    repeats: int = 3,
) -> dict:
    """Create a private run and record successes, skips and failures independently."""
    _zone(dos_timezone)
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 1:
        raise ValueError("repeat must be an integer >= 1")
    selected = list(dict.fromkeys(TOOLS if selected_tools is None else selected_tools))
    selected_profiles = list(dict.fromkeys(PROFILES if profiles is None else profiles))
    if (
        not selected
        or set(selected) - set(TOOLS)
        or not selected_profiles
        or set(selected_profiles) - set(PROFILES)
    ):
        raise ValueError("Unknown or empty tool/profile selection")
    output = _guard_path(output)
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    report: dict = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "run_directory": str(run),
        "report_path": str(run / "report.json"),
        "dos_timezone": dos_timezone,
        "selection": {"tools": selected, "profiles": selected_profiles, "repeat": repeats},
        "tools": {},
        "profiles": [],
        "measurements": [],
        "coverage": {},
        "limitations": [
            "CLI configurations are not GUI defaults.",
            "Metadata snapshot precedes payload reads; directory enumeration still occurs.",
            "NTFS delayed access-time updates, indexers and antivirus may affect observations.",
            "Current tool versions do not reproduce the complete historical paper environment.",
        ],
    }
    report["environment"] = _environment(output)
    supported = (
        os.name == "nt" and report["environment"].get("volume", {}).get("filesystem") == "NTFS"
    )
    for tool in sorted(set(selected) | {"7zip"}):
        info: dict = {
            "executable": str(tools[tool]) if tool in tools else None,
            "status": "skipped",
        }
        report["tools"][tool] = info
        if not supported:
            info["reason"] = "Requires Windows on NTFS"
        elif tool not in tools:
            info["reason"] = "Tool not installed; no replacement used"
        else:
            try:
                if not tools[tool].is_file():
                    raise ValueError(f"Invalid executable override: {tools[tool]}")
                info.update(version=tool_version(tools[tool]), status="available")
            except ERRORS as exc:
                info.update(status="failed", reason=str(exc))
    _save(report)
    for profile in selected_profiles:
        record: dict = {"profile": profile, "status": "skipped", "commands": []}
        report["profiles"].append(record)
        work = run / profile
        work.mkdir()
        expected: dict[str, bytes] = {}
        directories: list[str] = []
        references: dict = {}
        archive = work / "source.zip"
        if report["tools"]["7zip"]["status"] != "available":
            record["reason"] = "Source creation requires an available native 7zip"
        else:
            try:
                expected, directories, evidence = _source(work / "source")
                record.update(evidence)
                flags = [
                    f"-m{parameter}={'on' if profile == 'ntfs' else 'off'}"
                    for parameter in ("tc", "ta", "tm")
                ]
                run_command(
                    [str(tools["7zip"]), "a", "-tzip", "-y", *flags, str(archive), "set1"],
                    work / "source",
                    record["commands"],
                )
                references = validate_zip(archive, expected, directories, profile, dos_timezone)
                record.update(
                    status="generated",
                    archive=str(archive.relative_to(run)),
                    zip_sha256=sha256(archive),
                    references=references,
                    missing_directory_headers=[
                        name
                        for name in directories
                        if not references["entries"][name]["directory_header"]
                    ],
                )
            except ERRORS as exc:
                record.update(status="failed", reason=str(exc))
        _save(report)
        for tool in selected:
            for repeat in range(1, repeats + 1):
                measurement: dict = {
                    "id": f"{profile}-{tool}-{repeat}",
                    "profile": profile,
                    "tool": tool,
                    "repeat": repeat,
                    "status": "skipped",
                    "commands": [],
                }
                report["measurements"].append(measurement)
                if (
                    record["status"] != "generated"
                    or report["tools"][tool]["status"] != "available"
                ):
                    measurement["reason"] = "Source profile or extraction tool unavailable"
                    continue
                destination = work / f"{tool}-{repeat}"
                try:
                    prepare_destination(destination)
                    if sha256(archive) != record["zip_sha256"]:
                        raise ValueError("Source archive changed before extraction")
                    # The exact CLI invoked is the ground-truth extraction label.
                    if tool == "7zip":
                        argv = [str(tools[tool]), "x", "-y", f"-o{destination}", str(archive)]
                    else:
                        argv = [
                            str(tools[tool]),
                            "x",
                            "-cfg-",
                            "-inul",
                            "-ibck",
                            "-y",
                            str(archive),
                            str(destination) + os.sep,
                        ]
                    measurement.update(
                        destination=str(destination.relative_to(run)),
                        zip_sha256=record["zip_sha256"],
                    )
                    measurement["bounds"] = [ft.now_filetime()]
                    try:
                        run_command(argv, work, measurement["commands"])
                    finally:
                        measurement["bounds"].append(ft.now_filetime())
                    measurement["observations"] = snapshot_tree(destination)
                    measurement["validation"] = validate_extracted(
                        destination, expected, directories
                    )
                    if sha256(archive) != record["zip_sha256"]:
                        raise ValueError("Source archive changed during extraction")
                    measurement["analysis"] = analyze_observations(
                        measurement["observations"], references, tuple(measurement["bounds"])
                    )
                    measurement["status"] = "measured"
                except ERRORS as exc:
                    measurement.update(status="failed", reason=str(exc))
                _save(report)
    report["coverage"] = _coverage(report)
    _save(report)
    return report


def exit_code(report: dict, require_dod: bool = False) -> int:
    rows = [*report["profiles"], *report["measurements"], *report["tools"].values()]
    if any(row["status"] == "failed" for row in rows):
        return 1
    if not report["coverage"]["measured"] or require_dod and not report["coverage"]["dod_met"]:
        return 2
    return 0
