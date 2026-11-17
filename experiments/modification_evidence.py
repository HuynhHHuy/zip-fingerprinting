"""Bounded ZIP snapshots and deletion deltas, independent of provenance guesses."""

from copy import copy
import hashlib
import io
from pathlib import Path
import stat
import struct
import zipfile
import zlib

from experiments.decompression_pipeline import _guard_path, _safe_zip_name
from zip_fingerprint.parser import ZipBinaryParser

MAX_BYTES = 16 * 1024 * 1024


def _extra_records(raw: bytes) -> list[dict]:
    records: list[dict] = []
    while raw:
        if len(raw) < 4:
            raise ValueError("Truncated extra field")
        tag, size = struct.unpack_from("<HH", raw)
        body, raw = raw[4 : 4 + size], raw[4 + size :]
        if len(body) != size or tag in {r["id"] for r in records}:
            raise ValueError("Truncated or duplicate extra field")
        records.append({"id": tag, "size": size, "raw_hex": body.hex()})
    return records


def _identity(raw: bytes, flags: int, extras: list[dict], encoding: str) -> str:
    unicode_names = []
    for extra in extras:
        if extra["id"] == 0x7075:
            body = bytes.fromhex(extra["raw_hex"])
            if (
                len(body) < 6
                or body[0] != 1
                or struct.unpack_from("<I", body, 1)[0] != zlib.crc32(raw)
            ):
                raise ValueError("Invalid Unicode Path layout/CRC")
            unicode_names.append(body[5:].decode("utf-8", errors="strict"))
    if flags & 0x800:
        name = raw.decode("utf-8", errors="strict")
        if unicode_names and unicode_names != [name]:
            raise ValueError("Conflicting Unicode Path identity")
    elif unicode_names:
        name = unicode_names[0]
    else:
        name = raw.decode(encoding, errors="strict")
        if name.encode(encoding, errors="strict") != raw:
            raise ValueError("Lossy legacy name identity")
    if "\x00" in name:
        raise ValueError("NUL name")
    return _safe_zip_name(name)


def _header(raw: bytes, header: object, location: str, encoding: str) -> dict:
    values = dict(vars(header))
    start = values["offset"]
    fixed = 30 if location == "LFH" else 46
    name_start = start + fixed
    extra_start = name_start + values["file_name_length"]
    end = extra_start + values["extra_field_length"]
    raw_name = raw[name_start:extra_start]
    extras = _extra_records(raw[extra_start:end])
    values["file_name"] = _identity(raw_name, values["gp_bit_flag"], extras, encoding)
    values["extra_fields"] = extras
    values["extra_layout"] = [[e["id"], e["size"]] for e in extras]
    values["raw_name_hex"] = raw_name.hex()
    values["provenance_flags"] = values["gp_bit_flag"] & 0x808
    if "file_comment" in values:
        values["file_comment"] = values["file_comment"].hex()
        end += values["file_comment_length"]
    values["raw_header_hex"] = raw[start:end].hex()
    return values


def read_evidence(path: Path, encoding: str) -> dict:
    """Read only bounded regular ZIPs; no filesystem extraction or rewriting."""
    path = _guard_path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Archive exceeds size limit or is not a regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("Archive exceeds size limit")
    with ZipBinaryParser(raw) as parser:
        archive = parser.parse()
    locals_by_offset = {h.offset: h for h in archive.local_file_headers}
    entries: dict[str, dict] = {}
    seen = set()
    with zipfile.ZipFile(io.BytesIO(raw)) as stream:
        infos = stream.infolist()
        if len(infos) != len(archive.central_directory_headers):
            raise ValueError("Parser inventory disagreement")
        if sum(i.file_size for i in infos) > MAX_BYTES:
            raise ValueError("Uncompressed payload exceeds size limit")
        for central, info in zip(archive.central_directory_headers, infos):
            local = locals_by_offset[central.local_header_offset]
            lfh, cdh = [
                _header(raw, h, loc, encoding) for h, loc in [(local, "LFH"), (central, "CDH")]
            ]
            name = cdh["file_name"]
            if name != lfh["file_name"]:
                raise ValueError("LFH/CDH identity mismatch")
            if name.casefold() in seen:
                raise ValueError("Duplicate/aliased entry identity")
            seen.add(name.casefold())
            mode = stat.S_IFMT(info.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.external_attr & 0x400:
                raise ValueError("Unsupported ZIP entry type/link")
            if info.flag_bits & 1 or local.gp_bit_flag & 1:
                raise ValueError("Encrypted entries unsupported")
            if info.header_offset != central.local_header_offset:
                raise ValueError("Parser header offset disagreement")
            # zipfile checks raw LFH names, which can use a different encoding
            # from the CDH; the decoded identity agreement was verified above.
            read_info = copy(info)
            raw_local = bytes.fromhex(lfh["raw_name_hex"])
            read_info.orig_filename = raw_local.decode(
                "utf-8" if local.gp_bit_flag & 0x800 else "cp437"
            )
            payload = stream.read(read_info)  # CRC checked by zipfile.
            entries[name] = {
                "LFH": lfh,
                "CDH": cdh,
                "directory": info.is_dir(),
                "size": len(payload),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "entries": entries}


def compare_delete(before: dict, after: dict, target: str = "target.txt") -> dict:
    old, new = before["entries"], after["entries"]
    if target not in old or set(new) != set(old) - {target} or not new:
        raise ValueError("Unexpected deletion inventory")
    rows = []
    structural = {
        "version_made_by",
        "extract_version",
        "compression_method",
        "provenance_flags",
        "raw_name_hex",
        "extra_layout",
    }
    for name in sorted(new):
        if any(
            old[name][field] != new[name][field]
            for field in ("size", "payload_sha256", "directory")
        ):
            raise ValueError(f"Survivor payload changed: {name}")
        changes, qualifying = {}, []
        for location in ("LFH", "CDH"):
            left, right = old[name][location], new[name][location]
            for key in sorted(left.keys() | right.keys()):
                if left.get(key) != right.get(key):
                    label = f"{location}.{key}"
                    changes[label] = {"before": left.get(key), "after": right.get(key)}
                    if key in structural:
                        qualifying.append(label)
        rows.append({"path": name, "changes": changes, "qualifying_changes": qualifying})
    count = sum(bool(row["qualifying_changes"]) for row in rows)
    return {
        "payload_validation": True,
        "deleted": target,
        "entries": rows,
        "rewrite_scope": "all" if count == len(rows) else "partial" if count else "none",
        "global_rewrite": count == len(rows),
    }
