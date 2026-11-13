"""Generate labelled Windows CLI ZIP samples (PH6-DATA-002), not GUI profiles."""

import argparse
import base64
from contextlib import redirect_stdout
import ctypes
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from typing import Optional
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_corpus import create_standard_corpus  # noqa: E402
from simulate_modifications import (  # noqa: E402
    archive_command,
    discover_tools as discover_native_tools,
    run_command,
    sha256,
    tool_version,
)

APPLICATIONS = {
    "7zip": "7-Zip",
    "winrar": "WinRAR",
    "bandizip": "Bandizip",
    "powershell": "PowerShell Compress-Archive",
}
VARIANTS = ("root", "contents", "auxiliary")


def discover_tools() -> dict[str, Path]:
    tools = {key: path for key, path in discover_native_tools().items() if key in APPLICATIONS}
    powershell = shutil.which("powershell.exe") if os.name == "nt" else None
    if powershell:
        tools["powershell"] = Path(powershell).resolve()
    return tools


def _powershell(executable: Path, script: str) -> list[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return [str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def _quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _environment() -> dict:
    acp = int(ctypes.windll.kernel32.GetACP()) if os.name == "nt" else None
    offset = datetime.now().astimezone().utcoffset()
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "timezone_names": list(time.tzname),
        "utc_offset_seconds": int(offset.total_seconds()) if offset is not None else 0,
        "ansi_code_page": acp,
        "legacy_encoding": f"cp{acp}" if acp and acp != 65001 else "utf-8",
    }


def _check_path(path: Path, directory: bool) -> None:
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(f"Refusing link/reparse point: {item}")
        is_directory = item != path or directory
        if not (stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode)):
            raise ValueError(f"Unexpected output path type: {item}")
        if not is_directory and info.st_nlink != 1:
            raise ValueError(f"Refusing hard link: {item}")


def _catalogue(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": 1, "runs": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid catalogue JSON") from exc
    if data == {}:
        return {"schema_version": 1, "runs": []}
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "runs"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(data["runs"], list)
        or any(
            not isinstance(run, dict)
            or not isinstance(run.get("run_id"), str)
            or not isinstance(run.get("samples"), list)
            or not isinstance(run.get("metadata_path"), str)
            for run in data["runs"]
        )
    ):
        raise ValueError("Unsupported catalogue schema")
    return data


def _atomic_json(path: Path, data: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".metadata-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _entry_name(info: zipfile.ZipInfo, legacy_encoding: str) -> tuple[str, str]:
    if "\x00" in info.orig_filename:
        raise ValueError("Invalid archive path: NUL")
    if info.flag_bits & 0x800:
        return info.orig_filename, "utf8"
    raw = info.orig_filename.encode("cp437")
    extra = info.extra
    while len(extra) >= 4:
        header, size = struct.unpack_from("<HH", extra)
        payload, extra = extra[4 : 4 + size], extra[4 + size :]
        if (
            header == 0x7075
            and len(payload) >= 5
            and payload[0] == 1
            and struct.unpack_from("<I", payload, 1)[0] == zlib.crc32(raw)
        ):
            return payload[5:].decode("utf-8"), "unicode_path"
    return raw.decode(legacy_encoding), "legacy"


def validate_archive(
    path: Path, expected: dict[str, bytes], directories: list[str], legacy_encoding: str
) -> dict:
    """Validate only our tiny native samples, without extracting to disk."""
    files = []
    observed_directories = []
    seen = set()
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name, encoding = _entry_name(info, legacy_encoding)
            name = name.replace("\\", "/")
            parts = name.rstrip("/").split("/")
            if not name or any(p in ("", ".", "..") or ":" in p or "\x00" in p for p in parts):
                raise ValueError(f"Invalid archive path: {name!r}")
            canonical = name.rstrip("/")
            if canonical in seen:
                raise ValueError(f"Duplicate archive name: {name!r}")
            seen.add(canonical)
            if info.is_dir():
                if canonical not in directories:
                    raise ValueError(f"Unexpected directory inventory: {name!r}")
                if archive.read(info) != b"":
                    raise ValueError("Nonempty directory payload")
                observed_directories.append(canonical)
                continue
            if canonical not in expected:
                raise ValueError(f"Unexpected file inventory: {name!r}")
            if info.file_size != len(expected[canonical]):
                raise ValueError(f"Unexpected payload size: {name!r}")
            digest = hashlib.sha256(archive.read(info)).hexdigest()
            if digest != hashlib.sha256(expected[canonical]).hexdigest():
                raise ValueError(f"Unexpected payload checksum: {name!r}")
            files.append(
                {
                    "name": canonical,
                    "name_encoding": encoding,
                    "flag_bits": info.flag_bits,
                    "size": info.file_size,
                    "sha256": digest,
                }
            )
    if {row["name"] for row in files} != set(expected):
        raise ValueError("Incomplete file inventory")
    return {
        "passed": True,
        "files": files,
        "directory_headers": sorted(observed_directories),
        "missing_directory_headers": sorted(set(directories) - set(observed_directories)),
    }


def _source(source: Path, variant: str, baseline: dict) -> dict:
    with redirect_stdout(io.StringIO()):
        create_standard_corpus(source)
    manifest_path = source / "manifest.json"
    if json.loads(manifest_path.read_text(encoding="utf-8")) != baseline:
        raise ValueError("Source manifest differs from PH6-DATA-001 baseline")
    payloads = {}
    for entry in baseline["entries"]:
        if entry["type"] == "file":
            payload = (source / entry["path"]).read_bytes()
            if (
                len(payload) != entry["size"]
                or hashlib.sha256(payload).hexdigest() != entry["sha256"]
            ):
                raise ValueError(f"Source checksum mismatch: {entry['path']}")
            payloads[entry["path"]] = payload
    prefix = "auxiliary/" if variant == "auxiliary" else "set1/"
    names = {key: value for key, value in payloads.items() if key.startswith(prefix)}
    directories = [
        row["path"]
        for row in baseline["entries"]
        if row["type"] == "directory"
        and (row["path"] == prefix[:-1] or row["path"].startswith(prefix))
    ]
    cwd = source / "set1" if variant == "contents" else source
    inputs = ["2021.JPG", "Study", "emptyFolder"] if variant == "contents" else [prefix[:-1]]
    expected = {
        key[len(prefix) :] if variant == "contents" else key: value for key, value in names.items()
    }
    if variant == "contents":
        directories = [name[len(prefix) :] for name in directories if name != "set1"]
    manifest_hash = sha256(manifest_path)
    # All reads/enumeration above can affect atime. Restore using the public generator.
    with redirect_stdout(io.StringIO()):
        create_standard_corpus(source)
    times = []
    for name in sorted(names):
        info = (source / name).stat()
        times.append({"path": name, "mtime_ns": info.st_mtime_ns, "atime_ns": info.st_atime_ns})
    return {
        "cwd": cwd,
        "inputs": inputs,
        "expected": expected,
        "directories": directories,
        "payloads": names,
        "times": times,
        "manifest_sha256": manifest_hash,
    }


def _tool_info(tool: str, path: Path) -> dict:
    commands: list[dict] = []
    info = {
        "id": tool,
        "application": APPLICATIONS[tool],
        "executable": str(path),
        "interaction": "CLI",
        "commands": commands,
    }
    try:
        if tool == "powershell":
            script = (
                "$ErrorActionPreference='Stop';"
                "@{powershell_version=$PSVersionTable.PSVersion.ToString();"
                "archive_module_version=(Get-Command Compress-Archive -ErrorAction Stop)"
                ".Module.Version.ToString();archive_module_path="
                "(Get-Command Compress-Archive -ErrorAction Stop).Module.Path}"
                " | ConvertTo-Json -Compress"
            )
            run_command(_powershell(path, script), ROOT, commands)
            versions = json.loads(commands[-1]["stdout"])
            info["version"] = versions["archive_module_version"]
            info["powershell_version"] = versions["powershell_version"]
            info["archive_module_path"] = versions["archive_module_path"]
            info["version_probe_script"] = script
        else:
            info["version"] = tool_version(path)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        info["version_error"] = str(exc)
    return info


def generate(
    data_dir: Path,
    tools: dict[str, Path],
    selected_tools: Optional[list[str]] = None,
    variants: Optional[list[str]] = None,
) -> dict:
    """Append an immutable native run to a validated schema-v1 catalogue."""
    selected = list(dict.fromkeys(selected_tools if selected_tools is not None else APPLICATIONS))
    variants = list(dict.fromkeys(variants if variants is not None else VARIANTS))
    if (
        not selected
        or not variants
        or set(selected) - APPLICATIONS.keys()
        or set(variants) - set(VARIANTS)
    ):
        raise ValueError("Unknown or empty tool/variant selection")
    data_dir = Path(os.path.abspath(data_dir))
    catalogue_path = data_dir / "metadata.json"
    output = data_dir / "ground_truth"
    _check_path(data_dir, True)
    _check_path(output, True)
    _check_path(catalogue_path, False)
    catalogue = _catalogue(catalogue_path)
    baseline = json.loads((ROOT / "data/templates/manifest.json").read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    environment = _environment()
    report: dict = {
        "schema_version": 1,
        "run_id": run_dir.name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": environment,
        "metadata_path": (run_dir / "metadata.json").relative_to(data_dir).as_posix(),
        "tools": {},
        "samples": [],
        "limitations": [
            "CLI is not GUI equivalence",
            "Creation/change times are uncontrolled",
            "No BMAC or classifier accuracy measurement",
            "Single writer only",
        ],
    }
    for tool in selected:
        path = tools.get(tool) if os.name == "nt" else None
        info = _tool_info(tool, path) if path else None
        if info:
            report["tools"][tool] = info
        for variant in variants:
            record: dict = {
                "sample_id": f"{run_dir.name}_{tool}_{variant}",
                "tool_id": tool,
                "variant": variant,
                "commands": [],
                "started_utc": datetime.now(timezone.utc).isoformat(),
            }
            report["samples"].append(record)
            if path is None:
                record.update(status="skipped", reason="Missing tool or unsupported OS")
            elif info is None or "version_error" in info:
                record.update(status="failed", reason="Cannot establish tool version", tool=info)
            else:
                record["tool"] = info
                sample_dir = run_dir / f"{tool}-{variant}"
                source = sample_dir / "source"
                archive = sample_dir / "sample.zip"
                record["path"] = archive.relative_to(data_dir).as_posix()
                record["source_path"] = source.relative_to(data_dir).as_posix()
                try:
                    spec = _source(source, variant, baseline)
                    record["source_manifest_sha256"] = spec["manifest_sha256"]
                    record["source_times"] = spec["times"]
                    if tool == "powershell":
                        inputs = ",".join(_quote_ps(value) for value in spec["inputs"])
                        script = (
                            "$ErrorActionPreference='Stop'; Import-Module -Name "
                            + _quote_ps(info["archive_module_path"])
                            + "; Compress-Archive -LiteralPath @("
                            + inputs
                            + ") -DestinationPath "
                            + _quote_ps(str(archive))
                            + " -CompressionLevel Optimal"
                        )
                        args = _powershell(path, script)
                        record["powershell_script"] = script
                    else:
                        args = archive_command(tool, path, archive, spec["inputs"])
                    run_command(args, spec["cwd"], record["commands"])
                    record["validation"] = validate_archive(
                        archive,
                        spec["expected"],
                        spec["directories"],
                        environment["legacy_encoding"],
                    )
                    if any(
                        (source / key).read_bytes() != value
                        for key, value in spec["payloads"].items()
                    ):
                        raise ValueError("Archiver modified the source payload")
                    record.update(
                        status="generated",
                        sha256=sha256(archive),
                        size_bytes=archive.stat().st_size,
                    )
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    zipfile.BadZipFile,
                    zlib.error,
                    EOFError,
                    NotImplementedError,
                ) as exc:
                    record.update(status="failed", reason=str(exc))
            record["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        state: sum(row["status"] == state for row in report["samples"])
        for state in ("generated", "skipped", "failed")
    }
    _atomic_json(run_dir / "metadata.json", report)
    catalogue["runs"].append(report)
    _atomic_json(catalogue_path, catalogue)
    return report


def exit_code(report: dict) -> int:
    if report["summary"]["failed"]:
        return 1
    return 0 if report["summary"]["generated"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--tool", choices=APPLICATIONS, action="append")
    parser.add_argument("--variant", choices=VARIANTS, action="append")
    for tool in APPLICATIONS:
        parser.add_argument(f"--{tool}", type=Path, help="Override console executable")
    args = parser.parse_args()
    tools = discover_tools()
    for tool in APPLICATIONS:
        override = getattr(args, tool)
        if override is not None:
            if not override.is_file():
                parser.error(f"Not an executable file: {override}")
            tools[tool] = override.resolve()
    try:
        report = generate(args.data_dir, tools, args.tool, args.variant)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Ground-truth generation failed: {exc}\n")
    for sample in report["samples"]:
        print(sample["tool_id"], sample["variant"], sample["status"])
    print("Summary:", json.dumps(report["summary"]))
    print("Metadata:", ascii(str(args.data_dir / report["metadata_path"])))
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
