"""Header comparison against a baseline archive; synthetic archives, not native evidence."""

import dataclasses
import json

import pytest

from tests.integration.test_provenance_tracking import Entry, ntfs, parse, unicode_path
from zip_fingerprint.baseline import compare_archives

NAMES = ["keep.txt", "target.txt", "tieng-viet-ệ.txt", "가나다.txt"]


def sevenzip(name: str, data: bytes = b"forensic sample") -> Entry:
    return Entry(name, made_by=63, extract=10, central=[ntfs()], data=data)


def bandizip_rewrite(name: str) -> Entry:
    extras = [] if name.isascii() else [unicode_path(name)]
    return Entry(name, local=list(extras), central=list(extras))


def scored(result):
    return {row["path"]: row["qualifying_changes"] for row in result.entries}


def test_cascade_rewrite_of_every_survivor_is_all():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([bandizip_rewrite(name) for name in NAMES if name != "target.txt"])
    result = compare_archives(before, after)
    assert result.rewrite_scope == "all"
    assert result.case2_detected is True
    assert result.removed == ["target.txt"]
    assert result.added == []
    for qualifying in scored(result).values():
        assert "CDH.version_made_by" in qualifying


def test_offset_only_changes_are_none():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([sevenzip(name) for name in NAMES if name != "target.txt"])
    result = compare_archives(before, after)
    assert result.rewrite_scope == "none"
    assert result.case2_detected is False
    rows = {row["path"]: row for row in result.entries}
    moved = rows["tieng-viet-ệ.txt"]
    assert "LFH.offset" in moved["changes"]
    assert moved["qualifying_changes"] == []


def test_some_survivors_rewritten_is_partial():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([bandizip_rewrite("keep.txt")] + [sevenzip(name) for name in NAMES[2:]])
    result = compare_archives(before, after)
    assert result.rewrite_scope == "partial"
    assert result.case2_detected is False


def test_added_entry_is_listed_not_scored():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([sevenzip(name) for name in NAMES] + [Entry("added.txt")])
    result = compare_archives(before, after)
    assert result.added == ["added.txt"]
    assert "added.txt" not in scored(result)
    assert result.rewrite_scope == "none"


def test_rename_is_removed_plus_added():
    before = parse([sevenzip("a.txt"), sevenzip("b.txt")])
    after = parse([sevenzip("a.txt"), sevenzip("c.txt")])
    result = compare_archives(before, after)
    assert (result.removed, result.added, result.survivors) == (["b.txt"], ["c.txt"], ["a.txt"])


def test_survivor_content_change_blocks_case2():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse(
        [bandizip_rewrite("keep.txt")]
        + [dataclasses.replace(bandizip_rewrite(name), data=b"edited") for name in NAMES[1:2]]
        + [bandizip_rewrite(name) for name in NAMES[2:]]
    )
    result = compare_archives(before, after)
    assert result.content_changed == ["target.txt"]
    assert "target.txt" not in scored(result)
    assert result.rewrite_scope == "all"
    assert result.case2_detected is False


def test_identical_archives_are_none():
    archive = parse([sevenzip(name) for name in NAMES])
    result = compare_archives(archive, archive)
    assert result.rewrite_scope == "none"
    assert result.case2_detected is False
    assert all(row["changes"] == {} for row in result.entries)


def test_no_survivors_is_not_applicable():
    before = parse([sevenzip("a.txt")])
    after = parse([])
    result = compare_archives(before, after)
    assert result.rewrite_scope == "not_applicable"
    assert result.case2_detected is False
    assert result.removed == ["a.txt"]


def test_duplicate_names_are_refused():
    before = parse([sevenzip("a.txt"), sevenzip("a.txt")])
    after = parse([sevenzip("a.txt")])
    with pytest.raises(ValueError, match="Duplicate entry names"):
        compare_archives(before, after)
    with pytest.raises(ValueError, match="Duplicate entry names"):
        compare_archives(after, before)


def test_missing_local_header_is_a_change_not_a_crash():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([sevenzip(name) for name in NAMES])
    after.local_file_headers = []
    result = compare_archives(before, after)
    for row in result.entries:
        assert "LFH.extract_version" in row["qualifying_changes"]
        assert row["changes"]["LFH.extract_version"]["after"] is None
    assert result.rewrite_scope == "all"


def test_to_dict_is_json_serializable():
    before = parse([sevenzip(name) for name in NAMES])
    after = parse([bandizip_rewrite(name) for name in NAMES if name != "target.txt"])
    data = compare_archives(before, after).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["basis"] == "baseline_comparison"
    assert data["case2_detected"] is True
