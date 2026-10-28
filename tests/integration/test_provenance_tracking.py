"""Integration tests for archive modification and provenance tracking (Section 4.2, Figure 10).

Archives are assembled byte by byte so that every entry carries an explicit, independently chosen
fingerprint (host OS, LFH/CDH extra fields, 0x5455 lengths, data descriptor). Expected outcomes are
written by hand from Tables 6/7 and Section 4.2 rather than derived from ``rules.py``.
"""

from copy import deepcopy
from dataclasses import dataclass, field
import io
import json
import struct
from typing import List, Optional, Tuple
import zlib

import pytest

from zip_fingerprint.constants import (
    SIG_CENTRAL_DIRECTORY_HEADER,
    SIG_DATA_DESCRIPTOR,
    SIG_END_OF_CENTRAL_DIRECTORY,
    SIG_LOCAL_FILE_HEADER,
)
from zip_fingerprint.models import ZipArchiveRecord
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceReport, ProvenanceTracker

# 2021-01-11 11:30:59 UTC (paper sample time) as Windows FILETIME, whole second.
FILETIME_BASE = 1610364659 * 10_000_000 + 116444736000000000
NANO_FULL = 1234567  # 100-ns ticks -> "fffffff" (WinRAR / 7-Zip / Bandizip)
NANO_WINZIP = 1230000  # millisecond truncation -> "fff0000" (WinZip)
UNIX_TIME = 1610364659

Extra = Tuple[int, bytes]


# ----------------------------------------------------------------------------- payload helpers
def ntfs(nano: int = NANO_FULL) -> Extra:
    filetime = FILETIME_BASE + nano
    payload = struct.pack("<IHH", 0, 0x0001, 24) + struct.pack("<QQQ", filetime, filetime, filetime)
    return 0x000A, payload


def unicode_path(name: str) -> Extra:
    raw = name.encode("utf-8")
    return 0x7075, struct.pack("<BI", 1, zlib.crc32(raw)) + raw


def ext_ts(length: int) -> Extra:
    count = (length - 1) // 4
    return 0x5455, struct.pack("<B", (1 << count) - 1) + struct.pack(
        f"<{count}I", *[UNIX_TIME] * count
    )


def uid_gid(uid: int, gid: int) -> Extra:
    return 0x7875, struct.pack("<BBIBI", 1, 4, uid, 4, gid)


def unknown_field() -> Extra:
    return 0xBEEF, b"\x00\x01"


# ----------------------------------------------------------------------------- archive builder
@dataclass
class Entry:
    name: str
    host: int = 0
    local: List[Extra] = field(default_factory=list)
    central: List[Extra] = field(default_factory=list)
    descriptor: bool = False
    data: bytes = b"forensic sample"


def _extras(blocks: List[Extra]) -> bytes:
    return b"".join(struct.pack("<HH", hid, len(payload)) + payload for hid, payload in blocks)


def _flag(entry: Entry) -> int:
    """Bit 3 marks a data descriptor; bit 11 (EFS) marks UTF-8 names so they decode exactly."""
    return (0x0008 if entry.descriptor else 0) | (0 if entry.name.isascii() else 0x0800)


def build_zip(entries: List[Entry]) -> bytes:
    buf = io.BytesIO()
    offsets = []
    for entry in entries:
        offsets.append(buf.tell())
        name = entry.name.encode("utf-8")
        local = _extras(entry.local)
        crc = zlib.crc32(entry.data)
        flag = _flag(entry)
        header_crc, header_size = (0, 0) if entry.descriptor else (crc, len(entry.data))
        buf.write(
            struct.pack(
                "<IHHHHHIIIHH",
                SIG_LOCAL_FILE_HEADER,
                20,
                flag,
                0,
                0x5B9F,
                0x522B,
                header_crc,
                header_size,
                header_size,
                len(name),
                len(local),
            )
        )
        buf.write(name + local + entry.data)
        if entry.descriptor:
            buf.write(
                struct.pack("<IIII", SIG_DATA_DESCRIPTOR, crc, len(entry.data), len(entry.data))
            )
    cd_offset = buf.tell()
    for entry, offset in zip(entries, offsets):
        name = entry.name.encode("utf-8")
        central = _extras(entry.central)
        flag = _flag(entry)
        buf.write(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                SIG_CENTRAL_DIRECTORY_HEADER,
                (entry.host << 8) | 20,
                20,
                flag,
                0,
                0x5B9F,
                0x522B,
                zlib.crc32(entry.data),
                len(entry.data),
                len(entry.data),
                len(name),
                len(central),
                0,
                0,
                0,
                0x20,
                offset,
            )
        )
        buf.write(name + central)
    cd_size = buf.tell() - cd_offset
    buf.write(
        struct.pack(
            "<IHHHHIIH",
            SIG_END_OF_CENTRAL_DIRECTORY,
            0,
            0,
            len(entries),
            len(entries),
            cd_size,
            cd_offset,
            0,
        )
    )
    return buf.getvalue()


def parse(entries: List[Entry]) -> ZipArchiveRecord:
    with ZipBinaryParser(build_zip(entries)) as parser:
        return parser.parse()


def analyze(entries: List[Entry]) -> ProvenanceReport:
    return ProvenanceTracker(parse(entries)).analyze()


# ----------------------------------------------------------------------------- profile entries
def win_7zip(name: str, nano: int = NANO_FULL) -> Entry:
    return Entry(name, host=0, central=[ntfs(nano)])


def win_winrar(name: str) -> Entry:
    if name.isascii():
        return Entry(name, host=0, central=[ntfs()])
    return Entry(name, host=0, local=[unicode_path(name)], central=[ntfs(), unicode_path(name)])


def win_winzip(name: str) -> Entry:
    return Entry(
        name,
        host=0,
        local=[unicode_path(name)],
        central=[unicode_path(name), ntfs(NANO_WINZIP)],
    )


def win_bandizip_unicode(name: str) -> Entry:
    return Entry(name, host=0, local=[unicode_path(name)], central=[ntfs(), unicode_path(name)])


def win_compressed_folder(name: str) -> Entry:
    return Entry(name, host=0)


def mac_compress(name: str) -> Entry:
    blocks = [ext_ts(13), uid_gid(501, 20)]
    return Entry(name, host=3, local=list(blocks), central=list(blocks), descriptor=True)


def unix_zip_cli(name: str, uid: int = 1000, gid: int = 1000) -> Entry:
    return Entry(
        name,
        host=3,
        local=[ext_ts(9), uid_gid(uid, gid)],
        central=[ext_ts(5), uid_gid(uid, gid)],
    )


def environments(group) -> set:
    return set(group.candidates)


def indicator_codes(report: ProvenanceReport) -> set:
    return {indicator.code for indicator in report.indicators}


# ----------------------------------------------------------------------------- single provenance
@pytest.mark.parametrize(
    "entries",
    [
        [win_7zip("set1/"), win_7zip("set1/2021.JPG"), win_7zip("set1/Study/textsm.txt")],
        [mac_compress("set1/2021.JPG"), mac_compress("__MACOSX/set1/._2021.JPG")],
        [unix_zip_cli("set1/a.txt"), unix_zip_cli("set1/b.txt")],
        [win_compressed_folder("2021.JPG"), win_compressed_folder("Study/textsm.txt")],
    ],
    ids=["windows-7zip", "macos-compress", "ubuntu-zip", "windows-compressed-folder"],
)
def test_homogeneous_archives_are_single_provenance(entries):
    report = analyze(entries)
    assert report.is_multi_provenance is False
    assert report.case1_detected is False
    assert report.case2_detected is False
    assert len(report.groups) == 1
    assert report.groups[0].entry_names == [entry.name for entry in entries]
    assert report.inference_history


def test_unicode_path_variation_within_one_tool_is_not_multi_provenance():
    """WinRAR adds 0x7075 only for non-ASCII names; that alone is not a second source."""
    report = analyze([win_winrar("set1/2021.JPG"), win_winrar("set1/공부.txt")])
    assert report.is_multi_provenance is False
    assert len(report.groups) == 1
    assert ("Windows", "WinRAR") in environments(report.groups[0])
    assert ("Windows", "7-Zip") not in environments(report.groups[0])


def test_homogeneous_uncatalogued_tool_is_not_flagged():
    entries = [
        Entry("a.txt", host=0, central=[unknown_field()]),
        Entry("b.txt", host=0, central=[unknown_field()]),
    ]
    report = analyze(entries)
    assert report.is_multi_provenance is False
    assert report.groups[0].candidates == []
    assert any("catalog" in line.lower() for line in report.inference_history)


def test_empty_archive_reports_no_provenance_evidence():
    report = analyze([])
    assert report.is_multi_provenance is False
    assert report.groups == []
    assert report.entries == []
    assert any("no entries" in line.lower() for line in report.inference_history)


# ----------------------------------------------------------------------------- Case 1
def test_dod_two_entries_with_two_distinct_fingerprints_is_case1():
    """PH4-PROV-001 DoD: an artificial archive with two entries bearing two fingerprints."""
    report = analyze([win_7zip("set1/2021.JPG"), mac_compress("set1/added.txt")])
    assert report.is_multi_provenance is True
    assert report.case1_detected is True
    assert report.case2_detected is False
    assert {"MIXED_HOST_OS", "INCOMPATIBLE_ENTRY_FINGERPRINTS"} <= indicator_codes(report)
    original, modifier = report.groups
    assert original.entry_names == ["set1/2021.JPG"]
    assert original.role == "ORIGINAL_CREATOR_SUSPECT"
    assert ("Windows", "7-Zip") in environments(original)
    assert modifier.entry_names == ["set1/added.txt"]
    assert modifier.role == "MODIFIER_SUSPECT"
    # One entry cannot exclude Ubuntu Compress; UID/GID 501/20 ranks macOS first.
    assert environments(modifier) == {("macOS", "Compress"), ("Ubuntu", "Compress")}
    assert modifier.candidates[0] == ("macOS", "Compress")
    assert all(entry.host_os in (0, 3) for entry in report.entries)


def test_case1_add_with_same_host_os_is_detected_by_extra_field_heterogeneity():
    """Figure 10(a): SW1=7-Zip creates the archive, SW2=Windows Compressed folder adds one file."""
    report = analyze(
        [win_7zip("set1/"), win_7zip("set1/2021.JPG"), win_compressed_folder("set1/new.txt")]
    )
    assert report.is_multi_provenance is True
    assert report.case1_detected is True
    assert "MIXED_HOST_OS" not in indicator_codes(report)
    assert "INCOMPATIBLE_ENTRY_FINGERPRINTS" in indicator_codes(report)
    original, modifier = report.groups
    assert original.entry_names == ["set1/", "set1/2021.JPG"]
    assert modifier.entry_names == ["set1/new.txt"]
    assert environments(modifier) == {("Windows", "Compressed folder")}
    modifiers = {
        (item.target_os, item.application)
        for item in report.suspected_applications
        if item.role == "MODIFIER_SUSPECT"
    }
    assert modifiers == {("Windows", "Compressed folder")}


def test_case1_modify_middle_entry_by_other_os_tool():
    """Figure 10(c): SW1=WinZip; one existing entry rewritten by the Ubuntu zip CLI (SW2)."""
    report = analyze(
        [win_winzip("set1/가.txt"), unix_zip_cli("set1/나.txt"), win_winzip("set1/다.txt")]
    )
    assert report.case1_detected is True
    original, modifier = report.groups
    assert original.entry_names == ["set1/가.txt", "set1/다.txt"]
    assert original.candidates[0] == ("Windows", "WinZip")  # ordered by classifier evidence
    assert modifier.entry_names == ["set1/나.txt"]
    assert environments(modifier) == {("macOS", "zip"), ("Ubuntu", "zip")}


def test_case1_known_and_uncatalogued_entries_are_heterogeneous():
    report = analyze([win_7zip("a.txt"), Entry("b.txt", host=0, central=[unknown_field()])])
    assert report.is_multi_provenance is True
    assert "HETEROGENEOUS_STRUCTURE" in indicator_codes(report)
    assert len(report.groups) == 2


def test_overlapping_profiles_remain_undetectable_without_guessing():
    """Windows 7-Zip vs Bandizip with ASCII names share every high-weight feature."""
    report = analyze([win_7zip("a.txt"), win_7zip("b.txt")])
    assert report.is_multi_provenance is False


# ----------------------------------------------------------------------------- Case 2
def test_case2_global_cascade_after_delete_strips_central_extra_fields():
    """Figure 10(b): SW1=Bandizip (Unicode names), SW2=Compressed folder deletes a file and
    rewrites the central directory of every remaining entry without extra fields."""
    entries = []
    for name in ("set1/가.txt", "set1/나.txt"):
        entry = win_bandizip_unicode(name)
        entry.central = []  # rewritten by SW2; local header still from SW1
        entries.append(entry)
    report = analyze(entries)
    assert report.is_multi_provenance is True
    assert report.case2_detected is True
    assert report.case1_detected is False  # all remaining entries were rewritten uniformly
    (indicator,) = [item for item in report.indicators if item.code == "LFH_CDH_DISCREPANCY"]
    assert indicator.case == "CASE_2"
    assert indicator.scope == "ALL_ENTRIES"
    assert indicator.entries == ["set1/가.txt", "set1/나.txt"]
    by_role = {}
    for item in report.suspected_applications:
        by_role.setdefault(item.role, set()).add((item.target_os, item.application))
    assert ("Windows", "Bandizip") in by_role["ORIGINAL_CREATOR_SUSPECT"]
    assert ("Windows", "Compressed folder") not in by_role["ORIGINAL_CREATOR_SUSPECT"]
    assert by_role["MODIFIER_SUSPECT"] == {("Windows", "Compressed folder")}
    entry = report.entries[0]
    assert entry.lfh_cdh_consistent is False


def test_case2_timestamp_length_discrepancy_is_partial_scope():
    """LFH of macOS Compress (13-byte 0x5455 + descriptor) vs CDH of zip CLI (5-byte 0x5455)."""
    rewritten = mac_compress("set1/a.txt")
    rewritten.central = [ext_ts(5), uid_gid(501, 20)]
    report = analyze([rewritten, mac_compress("set1/b.txt")])
    assert report.case2_detected is True
    (indicator,) = [item for item in report.indicators if item.code == "LFH_CDH_DISCREPANCY"]
    assert indicator.scope == "PARTIAL"
    assert indicator.entries == ["set1/a.txt"]
    assert report.entries[1].lfh_cdh_consistent is True


# ----------------------------------------------------------------------------- subsidiary evidence
def test_mixed_nanosecond_patterns_are_subsidiary_only():
    """WinZip (fff0000) vs 7-Zip (fffffff) with identical high-weight structure."""
    report = analyze([win_7zip("a.txt", NANO_FULL), win_7zip("b.txt", NANO_WINZIP)])
    assert report.is_multi_provenance is False
    assert report.requires_further_analysis is True
    (indicator,) = [item for item in report.indicators if item.code == "MIXED_NANOSECOND_PATTERN"]
    assert indicator.weight == "SUBSIDIARY"
    assert sorted(indicator.entries) == ["a.txt", "b.txt"]


# ----------------------------------------------------------------------------- report contract
def test_report_dict_is_json_serializable_and_input_is_not_mutated():
    archive = parse([win_7zip("set1/2021.JPG"), mac_compress("set1/added.txt")])
    before = deepcopy(archive)
    tracker = ProvenanceTracker(archive)
    result = tracker.analyze_modifications()
    assert archive == before
    assert json.loads(json.dumps(result)) == result
    assert result["is_multi_provenance"] is True
    assert result["cases"] == {"case1_mixed_fingerprints": True, "case2_cascade_rewrite": False}
    assert {
        "groups",
        "indicators",
        "suspected_applications",
        "inference_history",
        "entries",
    } <= set(result)
    assert result == tracker.analyze().to_dict()


def test_roles_are_documented_as_heuristic():
    report = analyze([win_7zip("a.txt"), mac_compress("b.txt")])
    assert any("heuristic" in line.lower() for line in report.inference_history)
