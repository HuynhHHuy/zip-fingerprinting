"""Synthetic timestamp analysis tests; these do not measure decompression."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import zipfile

import pytest

from experiments import trace_decompression as tracer

M = 132548382591234567
A = 132863742557654321
B = 132232158571234567
BOUNDS = (134394336000000000, 134394336100000000)


def ntfs(mtime: int = M) -> bytes:
    body = struct.pack("<IHHQQQ", 0, 1, 24, mtime, A, B)
    return struct.pack("<HH", 0x000A, len(body)) + body


def make_zip(tmp_path: Path, extra: bytes = b"", date=(2021, 1, 11, 11, 30, 58)) -> Path:
    path = tmp_path / "dữ liệu.zip"
    with zipfile.ZipFile(path, "w") as archive:
        item = zipfile.ZipInfo("root/file.txt", date_time=date)
        item.extra = extra
        archive.writestr(item, b"payload")
        archive.writestr(zipfile.ZipInfo("empty/", date_time=date), b"")
    return path


def test_archive_references_preserve_raw_times_and_inventory(tmp_path: Path) -> None:
    path = make_zip(tmp_path, ntfs())
    refs = tracer.archive_references(path, "UTC")
    entry = refs["entries"]["root/file.txt"]
    assert entry["entry_type"] == "file"
    assert entry["context"] == {"status": "unique", "extra_field": 10, "reasons": []}
    assert {
        (r["header"], r["field"], r["ticks"]) for r in entry["references"] if r["label"] == "E"
    } == {
        (header, field, value)
        for header in ["LFH", "CDH"]
        for field, value in [("modified", M), ("accessed", A), ("birth", B)]
    }
    assert refs["entries"]["root"]["entry_type"] == "folder_no_header"
    assert refs["entries"]["empty"]["entry_type"] == "empty_folder"
    assert len(refs["zip_sha256"]) == 64
    assert entry["headers"][0]["extra_raw_hex"] == ntfs().hex()
    json.dumps(refs)


@pytest.mark.parametrize("date,count", [((2021, 11, 7, 1, 30, 0), 2), ((2021, 3, 14, 2, 30, 0), 0)])
def test_dst_fold_and_gap_are_not_guessed(tmp_path: Path, date: tuple, count: int) -> None:
    entry = tracer.archive_references(make_zip(tmp_path, date=date), "America/New_York")["entries"][
        "root/file.txt"
    ]
    assert len({r["ticks"] for r in entry["references"] if r["label"] == "H"}) == count
    if not count:
        assert "NONEXISTENT_DOS_LOCAL_TIME" in entry["headers"][0]["issues"]


def test_invalid_dos_clock_is_not_clamped(tmp_path: Path) -> None:
    path = make_zip(tmp_path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 10, 31 << 11)
    path.write_bytes(data)
    entry = tracer.archive_references(path, "UTC")["entries"]["root/file.txt"]
    assert "INVALID_DOS_TIME" in entry["headers"][0]["issues"]
    assert not [r for r in entry["references"] if r["header"] == "LFH"]
    assert entry["context"]["status"] != "unique"


@pytest.mark.parametrize("extra", [ntfs() + ntfs(), b"\x0a\x00\x20\x00bad", b"\x01"])
def test_duplicate_and_malformed_extras_preserved_without_table_lookup(
    tmp_path: Path, extra: bytes
) -> None:
    entry = tracer.archive_references(make_zip(tmp_path, extra), "UTC")["entries"]["root/file.txt"]
    assert entry["headers"][0]["extra_raw_hex"] == extra.hex()
    assert entry["context"]["status"] != "unique"


def test_lfh_cdh_conflict_retains_both_values(tmp_path: Path) -> None:
    path = make_zip(tmp_path, ntfs())
    data = bytearray(path.read_bytes())
    cd = data.index(b"PK\x01\x02")
    name_len = struct.unpack_from("<H", data, cd + 28)[0]
    struct.pack_into("<Q", data, cd + 46 + name_len + 12, M + 1)
    path.write_bytes(data)
    entry = tracer.archive_references(path, "UTC")["entries"]["root/file.txt"]
    assert {
        r["ticks"] for r in entry["references"] if r["label"] == "E" and r["field"] == "modified"
    } == {M, M + 1}
    assert entry["context"]["status"] == "ambiguous"


def test_extended_unix_ctime_is_not_birth(tmp_path: Path) -> None:
    extra = struct.pack("<HHBIII", 0x5455, 13, 7, 1610364659, 1641900655, 1578742257)
    entry = tracer.archive_references(make_zip(tmp_path, extra), "UTC")["entries"]["root/file.txt"]
    assert {r["field"] for r in entry["references"] if r["label"] == "E"} == {
        "modified",
        "accessed",
        "unix_ctime",
    }


def test_cdh_extended_timestamp_can_only_contain_mtime(tmp_path: Path) -> None:
    extra = struct.pack("<HHBI", 0x5455, 5, 1, 1610364659)
    path = make_zip(tmp_path, extra)
    data = bytearray(path.read_bytes())
    cd = data.index(b"PK\x01\x02")
    name_len = struct.unpack_from("<H", data, cd + 28)[0]
    data[cd + 46 + name_len + 4] = 7
    path.write_bytes(data)
    entry = tracer.archive_references(path, "UTC")["entries"]["root/file.txt"]
    assert entry["context"]["status"] == "unique"


@pytest.mark.parametrize(
    "observed,labels,status",
    [
        (50, ["H", "E"], "ambiguous"),
        (100, ["R"], "unique"),
        (200, ["R"], "unique"),
        (201, [], "unmatched"),
        (51, [], "unmatched"),
    ],
)
def test_matching_uses_exact_ticks_and_inclusive_real_bounds(
    observed: int, labels: list[str], status: str
) -> None:
    refs = [{"id": "h", "label": "H", "ticks": 50}, {"id": "e", "label": "E", "ticks": 50}]
    result = tracer.match_time_sources(observed, refs, (100, 200))
    assert result["labels"] == labels
    assert result["status"] == status
    assert result["deltas"][0]["delta_ticks"] == observed - 50


def test_multiple_labels_including_r_are_preserved() -> None:
    result = tracer.match_time_sources(100, [{"label": "E", "ticks": 100, "id": "e"}], (100, 200))
    assert result["labels"] == ["R", "E"]
    assert result["status"] == "ambiguous"


def test_invalid_bounds_are_rejected() -> None:
    with pytest.raises(ValueError):
        tracer.match_time_sources(100, [], (200, 100))


def test_analyze_uses_creation_reference_and_retains_table_ties(tmp_path: Path) -> None:
    refs = tracer.archive_references(make_zip(tmp_path, ntfs()), "UTC")
    result = tracer.analyze_observations(
        [{"path": "root/file.txt", "birth": B, "modified": M, "accessed": A, "changed": BOUNDS[0]}],
        refs,
        BOUNDS,
    )
    entry = result["entries"][0]
    assert entry["pattern"] == "EEER"
    assert entry["table8_candidates"] == ["WinZip", "7-Zip", "Bandizip"]
    assert result["coverage"]["missing_entries"] == ["empty", "root"]
    json.dumps(result)


def test_ambiguous_or_missing_field_does_not_produce_pattern(tmp_path: Path) -> None:
    refs = tracer.archive_references(make_zip(tmp_path), "UTC")
    observation = {
        "path": "root/file.txt",
        "birth": BOUNDS[0],
        "modified": None,
        "accessed": BOUNDS[0],
        "changed": BOUNDS[0],
    }
    result = tracer.analyze_observations([observation], refs, BOUNDS)
    entry = result["entries"][0]
    assert entry["pattern"] is None
    assert entry["table8_candidates"] == []
    assert entry["bmac"]["modified"]["status"] == "unavailable"
    assert result["time_reversal"][0]["status"] == "unavailable"


def test_reversal_one_tick_and_missing_parent_are_reported() -> None:
    observations = [
        {"path": "root/file", "birth": 101, "modified": 100, "accessed": 100, "changed": 100}
    ]
    result = tracer.analyze_observations(observations, {"entries": {}}, (1000, 2000))
    pair = result["time_reversal"][0]
    assert pair["status"] == "reversal"
    assert pair["delta_ticks"] == -1
    assert pair["analyzer_warnings"] == []
    assert pair["datetime_precision_lost"] is True
    assert all(pair["status"] == "unavailable" for pair in result["time_reversal"][1:])


def test_bad_timezone_has_actionable_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="timezone"):
        tracer.archive_references(make_zip(tmp_path), "Not/A/Timezone")


def test_cli_does_not_claim_native_extraction_is_implemented() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "experiments.trace_decompression", "--dos-timezone", "UTC"],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"Task 3" in result.stderr


def test_ntfs_internal_tag_size_is_validated(tmp_path: Path) -> None:
    extra = bytearray(ntfs())
    struct.pack_into("<H", extra, 10, 30)  # Claims more bytes than the tag contains.
    entry = tracer.archive_references(make_zip(tmp_path, bytes(extra)), "UTC")["entries"][
        "root/file.txt"
    ]
    assert entry["context"]["status"] != "unique"
    assert not [r for r in entry["references"] if r["label"] == "E"]


def test_conflicting_context_suppresses_table_lookup(tmp_path: Path) -> None:
    extra = ntfs() + struct.pack("<HHBI", 0x5455, 5, 1, 1610364659)
    refs = tracer.archive_references(make_zip(tmp_path, extra), "UTC")
    observation = {
        "path": "root/file.txt",
        "birth": B,
        "modified": M,
        "accessed": A,
        "changed": BOUNDS[0],
    }
    entry = tracer.analyze_observations([observation], refs, BOUNDS)["entries"][0]
    assert entry["pattern"] == "EEER"
    assert entry["context"]["status"] == "ambiguous"
    assert entry["table8_candidates"] == []


def test_h_e_collision_does_not_produce_pattern(tmp_path: Path) -> None:
    # H = 2021-01-11 11:30:58 UTC, Unix E has exactly the same instant.
    extra = struct.pack("<HHBI", 0x5455, 5, 1, 1610364658)
    refs = tracer.archive_references(make_zip(tmp_path, extra), "UTC")
    observation = {
        "path": "root/file.txt",
        "birth": BOUNDS[0],
        "modified": 132548382580000000,
        "accessed": BOUNDS[0],
        "changed": BOUNDS[0],
    }
    entry = tracer.analyze_observations([observation], refs, BOUNDS)["entries"][0]
    assert entry["bmac"]["modified"]["labels"] == ["H", "E"]
    assert entry["pattern"] is None
    assert entry["table8_candidates"] == []


def test_unix_5855_times_and_directory_header_classification(tmp_path: Path) -> None:
    extra = struct.pack("<HHII", 0x5855, 8, 1641900655, 1610364659)
    path = make_zip(tmp_path, extra)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("root/", b"")
    refs = tracer.archive_references(path, "UTC")
    assert refs["entries"]["root"]["entry_type"] == "folder_with_files"
    entry = refs["entries"]["root/file.txt"]
    assert entry["context"]["extra_field"] == 0x5855
    assert {r["field"] for r in entry["references"] if r["label"] == "E"} == {
        "modified",
        "accessed",
    }


def test_reversal_parent_pairs_equality_and_non_reversal() -> None:
    parent = {"path": "root", "birth": 100, "modified": 200, "accessed": 300, "changed": 400}
    child = {"path": "root/file", "birth": 100, "modified": 199, "accessed": 301, "changed": None}
    result = tracer.analyze_observations([parent, child], {"entries": {}}, (1000, 2000))
    pairs = {p["pair"]: p for p in result["time_reversal"] if p["path"] == "root/file"}
    assert pairs["child_parent_birth"]["status"] == "equal"
    assert pairs["child_parent_modified"]["status"] == "reversal"
    assert pairs["child_parent_accessed"]["status"] == "no-reversal"
    assert pairs["child_parent_changed"]["status"] == "unavailable"


def test_duplicate_observations_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate"):
        tracer.analyze_observations([{"path": "same"}, {"path": "same"}], {"entries": {}}, BOUNDS)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/drive", "a/../b", "a//b"])
def test_ambiguous_inventory_paths_rejected(tmp_path: Path, name: str) -> None:
    path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, b"payload")
    with pytest.raises(ValueError, match="ZIP path"):
        tracer.archive_references(path, "UTC")


def test_duplicate_archive_entries_rejected(tmp_path: Path) -> None:
    path = make_zip(tmp_path)
    with pytest.warns(UserWarning, match="Duplicate"):
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("root/file.txt", b"other payload")
    with pytest.raises(ValueError, match="Duplicate ZIP"):
        tracer.archive_references(path, "UTC")


@pytest.mark.parametrize("extra_id", [0x7075, 0x7875])
def test_malformed_nontimestamp_extra_suppresses_table_lookup(
    tmp_path: Path, extra_id: int
) -> None:
    extra = ntfs() + struct.pack("<HH", extra_id, 0)
    refs = tracer.archive_references(make_zip(tmp_path, extra), "UTC")
    evidence = refs["entries"]["root/file.txt"]
    assert evidence["headers"][0]["extra_fields"][-1]["status"] == "malformed"
    observation = {
        "path": "root/file.txt",
        "birth": B,
        "modified": M,
        "accessed": A,
        "changed": BOUNDS[0],
    }
    entry = tracer.analyze_observations([observation], refs, BOUNDS)["entries"][0]
    assert entry["context"]["status"] == "ambiguous"
    assert entry["table8_candidates"] == []


@pytest.mark.parametrize(
    "extra",
    [
        struct.pack("<HHBI", 0x7075, 6, 1, 0) + b"x",  # Wrong CRC.
        struct.pack("<HH", 0x7875, 3) + b"\x02\x00\x00",  # Unknown version.
    ],
)
def test_corrupt_whitelisted_layout_suppresses_context(tmp_path: Path, extra: bytes) -> None:
    entry = tracer.archive_references(make_zip(tmp_path, ntfs() + extra), "UTC")["entries"][
        "root/file.txt"
    ]
    assert entry["context"]["status"] != "unique"


def test_valid_uid_gid_extra_does_not_block_timestamp_lookup(tmp_path: Path) -> None:
    extra = ntfs() + struct.pack("<HH", 0x7875, 5) + b"\x01\x01\x01\x01\x02"
    entry = tracer.archive_references(make_zip(tmp_path, extra), "UTC")["entries"]["root/file.txt"]
    assert entry["context"]["status"] == "unique"
