"""Synthetic contracts, not evidence of a native Explorer operation."""

from copy import deepcopy
import io
import struct
import zipfile
import zlib

import pytest

from experiments.modification_evidence import compare_delete, read_evidence
from tests.integration.test_provenance_tracking import Entry, build_zip, ntfs


def snapshot(tmp_path, name, entries):
    path = tmp_path / name
    path.write_bytes(build_zip(entries))
    return read_evidence(path, "cp1252")


def test_global_rewrite_is_independent_of_tracker(tmp_path):
    survivors = [Entry(n, local=[ntfs()], central=[ntfs()]) for n in ["keep.txt", "가.txt"]]
    before = snapshot(tmp_path, "before.zip", [Entry("target.txt"), *survivors])
    changed = deepcopy(survivors)
    for entry in changed:
        entry.central = []
    after = snapshot(tmp_path, "after.zip", changed)
    result = compare_delete(before, after)
    assert result["payload_validation"] is True
    assert result["rewrite_scope"] == "all"
    assert result["global_rewrite"] is True
    assert all("CDH.extra_layout" in e["qualifying_changes"] for e in result["entries"])


def test_partial_and_no_rewrite(tmp_path):
    survivors = [Entry(n, local=[ntfs()], central=[ntfs()]) for n in ["a.txt", "b.txt"]]
    before = snapshot(tmp_path, "before.zip", [Entry("target.txt"), *survivors])
    unchanged = snapshot(tmp_path, "same.zip", survivors)
    result = compare_delete(before, unchanged)
    assert result["rewrite_scope"] == "none"  # Relocated headers are not Case 2.
    assert result["entries"][0]["changes"]
    changed = deepcopy(survivors)
    changed[0].central = []
    result = compare_delete(before, snapshot(tmp_path, "partial.zip", changed))
    assert result["rewrite_scope"] == "partial"
    assert result["global_rewrite"] is False


def test_timestamp_values_alone_do_not_qualify(tmp_path):
    before = snapshot(tmp_path, "b.zip", [Entry("target.txt"), Entry("keep", local=[ntfs(1)])])
    after = snapshot(tmp_path, "a.zip", [Entry("keep", local=[ntfs(2)])])
    result = compare_delete(before, after)
    assert result["rewrite_scope"] == "none"
    assert "LFH.extra_fields" in result["entries"][0]["changes"]


def test_forged_uncompressed_size_is_rejected(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as stream:
        stream.writestr("payload", b"x" * (32 * 1024 * 1024))
    raw = bytearray(buffer.getvalue())
    central = raw.index(b"PK\x01\x02")
    for crc_offset, size_offset in [(14, 22), (central + 16, central + 24)]:
        struct.pack_into("<I", raw, crc_offset, zlib.crc32(b"x"))
        struct.pack_into("<I", raw, size_offset, 1)
    path = tmp_path / "forged.zip"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="payload|size|deflate"):
        read_evidence(path, "cp1252")


@pytest.mark.parametrize(
    "entries",
    [[Entry("target.txt"), Entry("keep")], [Entry("other")], [Entry("keep", data=b"corrupt")], []],
)
def test_wrong_deletion_or_payload_is_rejected(tmp_path, entries):
    before = snapshot(tmp_path, "b.zip", [Entry("target.txt"), Entry("keep")])
    after = snapshot(tmp_path, "a.zip", entries)
    with pytest.raises(ValueError, match="inventory|payload"):
        compare_delete(before, after)


@pytest.mark.parametrize("names", [["../escape"], ["CON"], ["a", "A"], ["a", "a"]])
def test_unsafe_or_duplicate_names_rejected(tmp_path, names):
    with pytest.raises(ValueError):
        snapshot(tmp_path, "bad.zip", [Entry(n) for n in names])


@pytest.mark.parametrize("unicode_extra", [False, True])
def test_lossless_legacy_and_unicode_path(tmp_path, unicode_extra):
    path = tmp_path / "names.zip"
    raw_name = b"caf\xe9.txt"
    item = zipfile.ZipInfo("cafe.txt")
    if unicode_extra:
        body = struct.pack("<BI", 1, zlib.crc32(raw_name)) + "café.txt".encode()
        item.extra = struct.pack("<HH", 0x7075, len(body)) + body
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(item, b"payload")
    path.write_bytes(path.read_bytes().replace(b"cafe.txt", raw_name))
    result = read_evidence(path, "cp1252")
    assert set(result["entries"]) == {"café.txt"}
    assert result["entries"]["café.txt"]["LFH"]["raw_name_hex"] == raw_name.hex()


def test_bad_unicode_crc_and_lfh_name_conflict(tmp_path):
    path = tmp_path / "bad.zip"
    item = zipfile.ZipInfo("keep")
    item.extra = struct.pack("<HHBI", 0x7075, 9, 1, 0) + b"keep"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(item, b"payload")
    with pytest.raises(ValueError, match="Unicode"):
        read_evidence(path, "cp1252")
    path.write_bytes(build_zip([Entry("keep")]))
    raw = bytearray(path.read_bytes())
    raw[30:34] = b"else"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="identity"):
        read_evidence(path, "cp1252")


def test_snapshot_is_bounded_and_rejects_symlink_entry(tmp_path, monkeypatch):
    from experiments import modification_evidence as evidence

    path = tmp_path / "big.zip"
    path.write_bytes(build_zip([Entry("keep")]))
    monkeypatch.setattr(evidence, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="limit"):
        read_evidence(path, "cp1252")
    monkeypatch.setattr(evidence, "MAX_BYTES", 16 * 1024 * 1024)
    with zipfile.ZipFile(path, "w") as z:
        item = zipfile.ZipInfo("link")
        item.create_system = 3
        item.external_attr = 0o120777 << 16
        z.writestr(item, b"target")
    with pytest.raises(ValueError, match="type|link"):
        read_evidence(path, "cp1252")
