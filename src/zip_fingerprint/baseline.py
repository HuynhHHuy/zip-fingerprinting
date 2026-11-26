"""Case 2 evidence from a baseline: compare survivor headers of a before/after archive pair.

A single archive cannot show Case 2 once SW2 rewrites LFH and CDH consistently (issue #35):
nothing inside it disagrees any more. With the earlier archive at hand, the rewrite is
visible directly in the headers of the entries both archives share.

Only parsed header records are compared; nothing is decompressed. A survivor keeps its
content when CRC-32 and both sizes in its CDH are unchanged. The parser keeps decoded names,
not raw name bytes, so a change of name encoding is approximated by the UTF-8 flag (in
``provenance_flags``) and ``file_name_length``. Offsets, CRC, sizes, timestamps and comments
are listed as changes but never qualify on their own. This comparison says nothing about
Case 2 when only one archive is available.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from zip_fingerprint.models import (
    CentralDirectoryHeaderRecord,
    ExtraFieldBlock,
    LocalFileHeaderRecord,
    ZipArchiveRecord,
)

# Same structural fields as experiments/modification_evidence.compare_survivors.
QUALIFYING_FIELDS = frozenset(
    {
        "version_made_by",
        "extract_version",
        "compression_method",
        "provenance_flags",
        "file_name_length",
        "extra_layout",
    }
)
PROVENANCE_FLAG_MASK = 0x0808  # bit 3 data descriptor, bit 11 UTF-8 name

SCOPE_ALL = "all"
SCOPE_PARTIAL = "partial"
SCOPE_NONE = "none"
SCOPE_NOT_APPLICABLE = "not_applicable"


@dataclass
class BaselineComparison:
    """Header changes of the entries shared by a baseline and a later archive."""

    survivors: List[str]
    removed: List[str]
    added: List[str]
    content_changed: List[str]
    entries: List[Dict[str, Any]]
    rewrite_scope: str
    case2_detected: bool
    basis: str = "baseline_comparison"
    limitations: List[str] = field(
        default_factory=lambda: [
            "Header-only comparison; payloads are not decompressed.",
            "Name encoding changes are approximated by the UTF-8 flag and name length.",
        ]
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "basis": self.basis,
            "survivors": list(self.survivors),
            "removed": list(self.removed),
            "added": list(self.added),
            "content_changed": list(self.content_changed),
            "entries": [dict(row) for row in self.entries],
            "rewrite_scope": self.rewrite_scope,
            "case2_detected": self.case2_detected,
            "limitations": list(self.limitations),
        }


def _layout(blocks: List[ExtraFieldBlock]) -> List[List[int]]:
    return [[block.header_id, block.data_size] for block in blocks]


def _local_fields(lfh: Optional[LocalFileHeaderRecord]) -> Dict[str, Any]:
    keys = (
        "extract_version",
        "compression_method",
        "provenance_flags",
        "file_name_length",
        "extra_layout",
        "offset",
        "crc32",
        "compressed_size",
        "uncompressed_size",
        "last_mod_time",
        "last_mod_date",
    )
    if lfh is None:
        return dict.fromkeys(keys)
    return {
        "extract_version": lfh.extract_version,
        "compression_method": lfh.compression_method,
        "provenance_flags": lfh.gp_bit_flag & PROVENANCE_FLAG_MASK,
        "file_name_length": lfh.file_name_length,
        "extra_layout": _layout(lfh.extra_fields),
        "offset": lfh.offset,
        "crc32": lfh.crc32,
        "compressed_size": lfh.compressed_size,
        "uncompressed_size": lfh.uncompressed_size,
        "last_mod_time": lfh.last_mod_time,
        "last_mod_date": lfh.last_mod_date,
    }


def _central_fields(cdh: CentralDirectoryHeaderRecord) -> Dict[str, Any]:
    return {
        "version_made_by": cdh.version_made_by,
        "extract_version": cdh.extract_version,
        "compression_method": cdh.compression_method,
        "provenance_flags": cdh.gp_bit_flag & PROVENANCE_FLAG_MASK,
        "file_name_length": cdh.file_name_length,
        "extra_layout": _layout(cdh.extra_fields),
        "offset": cdh.local_header_offset,
        "crc32": cdh.crc32,
        "compressed_size": cdh.compressed_size,
        "uncompressed_size": cdh.uncompressed_size,
        "last_mod_time": cdh.last_mod_time,
        "last_mod_date": cdh.last_mod_date,
        "file_comment": cdh.file_comment.hex(),
    }


def _index(archive: ZipArchiveRecord) -> Dict[str, Dict[str, Any]]:
    counts = Counter(cdh.file_name for cdh in archive.central_directory_headers)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"Duplicate entry names: {', '.join(duplicates)}")
    by_offset = {lfh.offset: lfh for lfh in archive.local_file_headers}
    return {
        cdh.file_name: {
            "LFH": _local_fields(by_offset.get(cdh.local_header_offset)),
            "CDH": _central_fields(cdh),
        }
        for cdh in archive.central_directory_headers
    }


def _same_content(old: Dict[str, Any], new: Dict[str, Any]) -> bool:
    return all(
        old["CDH"][key] == new["CDH"][key]
        for key in ("crc32", "compressed_size", "uncompressed_size")
    )


def compare_archives(before: ZipArchiveRecord, after: ZipArchiveRecord) -> BaselineComparison:
    """Score how many surviving entries had a structural header field rewritten."""
    old, new = _index(before), _index(after)
    survivors = sorted(old.keys() & new.keys())
    content_changed = [name for name in survivors if not _same_content(old[name], new[name])]
    rows: List[Dict[str, Any]] = []
    for name in survivors:
        if name in content_changed:
            continue
        changes: Dict[str, Dict[str, Any]] = {}
        qualifying: List[str] = []
        for location in ("LFH", "CDH"):
            left, right = old[name][location], new[name][location]
            for key in sorted(left.keys() | right.keys()):
                if left.get(key) != right.get(key):
                    label = f"{location}.{key}"
                    changes[label] = {"before": left.get(key), "after": right.get(key)}
                    if key in QUALIFYING_FIELDS:
                        qualifying.append(label)
        rows.append({"path": name, "changes": changes, "qualifying_changes": qualifying})

    rewritten = sum(bool(row["qualifying_changes"]) for row in rows)
    if not rows:
        scope = SCOPE_NOT_APPLICABLE
    elif rewritten == len(rows):
        scope = SCOPE_ALL
    elif rewritten:
        scope = SCOPE_PARTIAL
    else:
        scope = SCOPE_NONE
    return BaselineComparison(
        survivors=survivors,
        removed=sorted(old.keys() - new.keys()),
        added=sorted(new.keys() - old.keys()),
        content_changed=content_changed,
        entries=rows,
        rewrite_scope=scope,
        case2_detected=scope == SCOPE_ALL and not content_changed,
    )
