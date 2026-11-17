"""ZIP timestamp evidence and BMAC analysis; native extraction awaits Task 3.

These functions analyze observations, never produce native evidence themselves.
All matching uses integer FILETIME ticks; ambiguous sources remain ambiguous.
Directory inventory currently requires slash-terminated directory headers. The
shared NTFS/0x5855 decoders omit zero timestamps; raw extra bytes remain in the
report. These restrictions need reassessment before accepting arbitrary ZIPs.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import struct
import sys
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from experiments.windows_filetimes import filetime_utc  # noqa: E402
from zip_fingerprint.decompression import DecompressionAnalyzer  # noqa: E402
from zip_fingerprint.extractor import dos_to_datetime  # noqa: E402
from zip_fingerprint.extra_fields import ExtraFieldParser  # noqa: E402
from zip_fingerprint.parser import ZipBinaryParser  # noqa: E402

TICKS = 10_000_000
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FIELDS = ("birth", "modified", "accessed", "changed")
TIME_IDS = {0x000A, 0x5455, 0x5855}


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"Unavailable DOS timezone {name!r}; use an IANA name and install "
            "the dependencies: pip install -e '.[dev,experiments]'"
        ) from exc


def _ticks(value: datetime) -> int:
    delta = value.astimezone(timezone.utc) - EPOCH
    return (delta.days * 86400 + delta.seconds) * TICKS + delta.microseconds * 10


def _reference(
    label: str,
    header: str,
    field: str,
    ticks: int,
    resolution: int,
    extra_id: int | None = None,
    occurrence: int = 0,
) -> dict[str, Any]:
    try:
        utc = filetime_utc(ticks)
    except ValueError:
        utc = None  # Preserve raw integers even outside the displayable date range.
    return {
        "id": f"{header}:{extra_id}:{occurrence}:{field}:{ticks}",
        "label": label,
        "header": header,
        "field": field,
        "extra_field_id": extra_id,
        "ticks": ticks,
        "utc": utc,
        "resolution_ticks": resolution,
    }


def _dos_references(header: Any, location: str, zone: ZoneInfo) -> tuple[list[dict], list[str]]:
    time, date = header.last_mod_time, header.last_mod_date
    # The shared helper clamps invalid clocks; first validate the forensic input.
    if (time >> 11) > 23 or ((time >> 5) & 63) > 59 or (time & 31) > 29:
        return [], ["INVALID_DOS_TIME"]
    local = dos_to_datetime(time, date)
    if local is None:
        return [], ["INVALID_DOS_TIME"]
    candidates = set()
    for fold in (0, 1):
        utc = local.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
        if utc.astimezone(zone).replace(tzinfo=None) == local:
            candidates.add(_ticks(utc))
    issues = []
    if not candidates:
        issues.append("NONEXISTENT_DOS_LOCAL_TIME")
    elif len(candidates) > 1:
        issues.append("AMBIGUOUS_DOS_LOCAL_TIME")
    return [_reference("H", location, "modified", t, 2 * TICKS) for t in sorted(candidates)], issues


def _decode_times(extra_id: int, data: bytes, location: str) -> list[tuple[str, int]]:
    """Validate timestamp layouts before using shared tolerant decoders."""
    if extra_id == 0x000A:
        if len(data) != 32 or struct.unpack_from("<HH", data, 4) != (1, 24):
            raise ValueError("Unsupported or malformed NTFS timestamp tag")
        result = ExtraFieldParser.decode_ntfs(data)
        if result is None:
            raise ValueError("Invalid NTFS timestamp layout")
        return [
            (field, value)
            for field, value in [
                ("modified", result.mtime_filetime),
                ("accessed", result.atime_filetime),
                ("birth", result.ctime_filetime),
            ]
            if value != 0
        ]
    if extra_id == 0x5455:
        if not data or data[0] & ~7:
            raise ValueError("Invalid extended timestamp flags")
        required = 1 + 4 * sum(bool(data[0] & mask) for mask in (1, 2, 4))
        # Info-ZIP CDH can retain all flags but store only mtime.
        if len(data) != required and not (location == "CDH" and len(data) == 5 and data[0] & 1):
            raise ValueError("Invalid extended timestamp length")
        decoded = ExtraFieldParser.decode_extended_timestamp(data)
        if decoded is None:
            raise ValueError("Invalid extended timestamp")
        values = [
            ("modified", decoded.mtime),
            ("accessed", decoded.atime),
            ("unix_ctime", decoded.ctime),
        ]
    else:
        if len(data) not in (8, 12):
            raise ValueError("Invalid Unix timestamp length")
        unix = ExtraFieldParser.decode_unix_5855(data)
        if unix is None:
            raise ValueError("Invalid Unix timestamp")
        values = [("modified", unix.mtime), ("accessed", unix.atime)]
    return [(field, _ticks(value)) for field, value in values if value is not None]


def _validate_metadata_extra(extra_id: int, data: bytes, raw_name: bytes) -> None:
    """Validate the non-timestamp layouts accepted by the table context."""
    if extra_id == 0x7075:
        decoded = ExtraFieldParser.decode_unicode_path(data)
        if decoded is None or decoded.version != 1 or not data[5:]:
            raise ValueError("Invalid Unicode Path layout")
        data[5:].decode("utf-8", errors="strict")
        if decoded.name_crc32 != zlib.crc32(raw_name):
            raise ValueError("Unicode Path CRC does not match the header filename")
    elif extra_id == 0x7875:
        decoded_ids = ExtraFieldParser.decode_unix_uid_gid(data)
        if decoded_ids is None or decoded_ids.version != 1 or data[1] == 0:
            raise ValueError("Invalid UID/GID layout")
        gid_size_offset = 2 + data[1]
        if data[gid_size_offset] == 0 or gid_size_offset + 1 + data[gid_size_offset] != len(data):
            raise ValueError("Invalid UID/GID length")


def _header_references(header: Any, location: str, zone: ZoneInfo, raw: bytes) -> dict[str, Any]:
    refs, issues = _dos_references(header, location, zone)
    start = header.offset + (30 if location == "LFH" else 46) + header.file_name_length
    extra = raw[start : start + header.extra_field_length]
    records: list[dict] = []
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            issues.append("TRUNCATED_EXTRA_HEADER")
            break
        extra_id, size = struct.unpack_from("<HH", extra, cursor)
        body = extra[cursor + 4 : cursor + 4 + size]
        record = {"id": extra_id, "declared_size": size, "raw_hex": body.hex(), "status": "valid"}
        records.append(record)
        if len(body) != size:
            record["status"] = "malformed"
            issues.append("TRUNCATED_EXTRA_PAYLOAD")
        elif extra_id in TIME_IDS:
            try:
                values = _decode_times(extra_id, body, location)
                refs.extend(
                    _reference(
                        "E",
                        location,
                        field,
                        ticks,
                        1 if extra_id == 10 else TICKS,
                        extra_id,
                        len(records),
                    )
                    for field, ticks in values
                )
            except (ValueError, OverflowError, OSError) as exc:
                record.update(status="malformed", error=str(exc))
                issues.append("INVALID_TIMESTAMP_EXTRA")
        elif extra_id in {0x7075, 0x7875}:
            try:
                name_start = header.offset + (30 if location == "LFH" else 46)
                _validate_metadata_extra(extra_id, body, raw[name_start:start])
            except ValueError as exc:
                record.update(status="malformed", error=str(exc))
                issues.append("INVALID_METADATA_EXTRA")
        cursor += 4 + size
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        issues.append("DUPLICATE_EXTRA_ID")
    return {
        "location": location,
        "offset": header.offset,
        "dos_time": header.last_mod_time,
        "dos_date": header.last_mod_date,
        "extra_raw_hex": extra.hex(),
        "extra_fields": records,
        "references": refs,
        "issues": issues,
    }


def _context(headers: list[dict]) -> dict[str, Any]:
    reasons = sorted({issue for header in headers for issue in header["issues"]})
    ids = {extra["id"] for header in headers for extra in header["extra_fields"]}
    timestamp_ids = ids & TIME_IDS
    if len(timestamp_ids) > 1:
        reasons.append("MULTIPLE_TIMESTAMP_IDS")
    if ids - TIME_IDS - {0x7075, 0x7875}:
        reasons.append("UNSUPPORTED_EXTRA_ID")
    if len({(h["dos_time"], h["dos_date"]) for h in headers}) > 1:
        reasons.append("LFH_CDH_DOS_CONFLICT")
    values: dict[tuple, set[int]] = {}
    for header in headers:
        for ref in header["references"]:
            if ref["label"] == "E":
                values.setdefault((ref["extra_field_id"], ref["field"]), set()).add(ref["ticks"])
    if any(len(v) > 1 for v in values.values()):
        reasons.append("LFH_CDH_EXTRA_CONFLICT")
    return {
        "status": "ambiguous" if reasons else "unique",
        "extra_field": next(iter(timestamp_ids)) if len(timestamp_ids) == 1 else None,
        "reasons": reasons,
    }


def _path(name: str) -> str:
    key = name.replace("\\", "/").removesuffix("/")
    if not key or ":" in key or "\x00" in key or any(p in ("", ".", "..") for p in key.split("/")):
        raise ValueError(f"Unsafe or ambiguous ZIP path: {name!r}")
    return key


def archive_references(path: Path, dos_timezone: str) -> dict:
    """Collect evidence from a single ZIP snapshot, including inferred folders."""
    zone = _zone(dos_timezone)
    raw = path.read_bytes()
    with ZipBinaryParser(raw) as parser:
        archive = parser.parse()
    locals_by_offset = {header.offset: header for header in archive.local_file_headers}
    entries: dict[str, dict] = {}
    for central in archive.central_directory_headers:
        key = _path(central.file_name)
        if key in entries:
            raise ValueError(f"Duplicate ZIP entry: {key}")
        local = locals_by_offset[central.local_header_offset]
        headers = [
            _header_references(local, "LFH", zone, raw),
            _header_references(central, "CDH", zone, raw),
        ]
        if local.file_name != central.file_name:
            headers[0]["issues"].append("LFH_CDH_NAME_CONFLICT")
        entries[key] = {
            "path": key,
            "directory_header": central.file_name.endswith(("/", "\\")),
            "headers": headers,
            "references": [r for h in headers for r in h["references"]],
            "context": _context(headers),
        }
    for key in list(entries):
        parts = key.split("/")
        for depth in range(1, len(parts)):
            parent = "/".join(parts[:depth])
            if (
                parent in entries
                and not entries[parent]["directory_header"]
                and entries[parent]["headers"]
            ):
                raise ValueError(f"ZIP file used as a directory: {parent}")
            entries.setdefault(
                parent,
                {
                    "path": parent,
                    "directory_header": False,
                    "headers": [],
                    "references": [],
                    "context": _context([]),
                },
            )
    for key, entry in entries.items():
        descendants = any(other.startswith(key + "/") for other in entries)
        entry["entry_type"] = (
            "folder_with_files"
            if entry["directory_header"] and descendants
            else (
                "empty_folder"
                if entry["directory_header"]
                else "folder_no_header" if not entry["headers"] else "file"
            )
        )
    return {
        "schema_version": 1,
        "zip_sha256": hashlib.sha256(raw).hexdigest(),
        "dos_timezone": dos_timezone,
        "entries": entries,
    }


def _validate_bounds(bounds: tuple[int, int]) -> None:
    if len(bounds) != 2 or any(isinstance(t, bool) or not isinstance(t, int) for t in bounds):
        raise ValueError("R bounds must be two integer FILETIME values")
    if not 0 <= bounds[0] <= bounds[1] < 1 << 64:
        raise ValueError("R bounds must be ordered unsigned FILETIME values")


def match_time_sources(observed: int, references: list[dict], bounds: tuple[int, int]) -> dict:
    """Keep exact H/E matches and inclusive R matches; do not rank sources."""
    _validate_bounds(bounds)
    if isinstance(observed, bool) or not isinstance(observed, int) or not 0 <= observed < 1 << 64:
        raise ValueError("Observed timestamp must be an unsigned integer FILETIME")
    matches = []
    deltas = []
    if bounds[0] <= observed <= bounds[1]:
        matches.append({"label": "R", "bounds": list(bounds)})
    for ref in references:
        if ref["label"] not in ("H", "E"):
            raise ValueError("Header reference must have H or E label")
        delta = observed - ref["ticks"]
        deltas.append({"id": ref["id"], "delta_ticks": delta})
        if delta == 0:
            matches.append(dict(ref))
    labels = [label for label in ("R", "H", "E") if any(m["label"] == label for m in matches)]
    return {
        "status": "unique" if len(labels) == 1 else "ambiguous" if labels else "unmatched",
        "observed": observed,
        "labels": labels,
        "matches": matches,
        "deltas": deltas,
    }


def _reversal(
    path: str, pair: str, earlier: int | None, later: int | None, folder: bool = False
) -> dict:
    result: dict[str, Any] = {
        "path": path,
        "pair": pair,
        "status": "unavailable",
        "delta_ticks": None,
        "analyzer_warnings": [],
        "datetime_precision_lost": False,
    }
    if earlier is None or later is None:
        return result
    delta = earlier - later
    result.update(
        status="reversal" if delta < 0 else "equal" if delta == 0 else "no-reversal",
        delta_ticks=delta,
        datetime_precision_lost=bool(earlier % 10 or later % 10),
    )
    try:
        first, second = [EPOCH + timedelta(microseconds=t // 10) for t in (earlier, later)]
    except OverflowError:
        result["analyzer_status"] = "unavailable_datetime_range"
        return result
    analyzer = DecompressionAnalyzer()
    result["analyzer_warnings"] = (
        analyzer.check_time_reversal(parent_folder_time=second, subfolder_time=first)
        if folder
        else analyzer.check_time_reversal(creation_time=second, mod_time=first)
    )
    return result


def analyze_observations(
    observations: list[dict], references: dict, bounds: tuple[int, int]
) -> dict:
    """Missing or ambiguous evidence never forces a BMAC pattern or table match."""
    _validate_bounds(bounds)
    by_path: dict[str, dict] = {}
    for observation in observations:
        key = _path(observation["path"])
        if key in by_path:
            raise ValueError(f"Duplicate observation: {key}")
        by_path[key] = observation
    entries = []
    reversals = []
    for path, observation in by_path.items():
        evidence = references["entries"].get(path)
        bmac = {}
        for field in FIELDS:
            value = observation.get(field)
            bmac[field] = (
                {
                    "status": "unavailable",
                    "observed": None,
                    "labels": [],
                    "matches": [],
                    "deltas": [],
                }
                if value is None
                else match_time_sources(value, evidence["references"] if evidence else [], bounds)
            )
        pattern = None
        candidates = []
        if evidence and all(value["status"] == "unique" for value in bmac.values()):
            pattern = "".join(bmac[field]["labels"][0] for field in FIELDS)
            if evidence["context"]["status"] == "unique":
                candidates = DecompressionAnalyzer().identify_decompressor(
                    pattern, evidence["entry_type"], evidence["context"]["extra_field"]
                )
        entries.append(
            {
                "path": path,
                "bmac": bmac,
                "pattern": pattern,
                "entry_type": evidence["entry_type"] if evidence else None,
                "context": evidence["context"] if evidence else {"status": "unavailable"},
                "table8_candidates": candidates,
            }
        )
        reversals.append(
            _reversal(path, "modified_birth", observation.get("modified"), observation.get("birth"))
        )
        parent = path.rpartition("/")[0]
        if parent:
            for field in FIELDS:
                reversals.append(
                    _reversal(
                        path,
                        f"child_parent_{field}",
                        observation.get(field),
                        by_path.get(parent, {}).get(field),
                        folder=True,
                    )
                )
    return {
        "entries": entries,
        "time_reversal": reversals,
        "bounds": list(bounds),
        "coverage": {
            "observed_entries": len(entries),
            "missing_entries": sorted(references["entries"].keys() - by_path.keys()),
            "unexpected_entries": sorted(by_path.keys() - references["entries"].keys()),
            "assessed_pairs": sum(r["status"] != "unavailable" for r in reversals),
            "unavailable_pairs": sum(r["status"] == "unavailable" for r in reversals),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dos-timezone", required=True, help="IANA zone for ZIP DOS timestamps")
    args = parser.parse_args(argv)
    try:
        _zone(args.dos_timezone)
    except ValueError as exc:
        parser.error(str(exc))
    sys.stderr.write("Native extraction pipeline is not implemented yet (Task 3).\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
