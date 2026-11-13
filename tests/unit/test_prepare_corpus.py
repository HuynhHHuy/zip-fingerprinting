"""Independent format, reproducibility and safety checks for PH6-DATA-001."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET
import zipfile

from PIL import Image
import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare_corpus.py"
spec = importlib.util.spec_from_file_location("prepare_corpus", SCRIPT)
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
FIXED_NS = 1610364659000000000
BASE_PATHS = {
    "set1",
    "set1/Study",
    "set1/emptyFolder",
    "set1/2021.JPG",
    "set1/Study/capture.JPG",
    "set1/Study/Sample.docx",
    "set1/Study/textsm.txt",
}
AUX_PATHS = {
    "auxiliary",
    "auxiliary/double_zip",
    "auxiliary/double_zip/inner.zip",
    "auxiliary/encodings",
    "auxiliary/encodings/korean-cp949.txt",
    "auxiliary/korean_nfc",
    "auxiliary/korean_nfc/가나다.txt",
    "auxiliary/korean_nfd",
    "auxiliary/korean_nfd/가나다.txt",
    "auxiliary/vietnamese",
    "auxiliary/vietnamese/tiếng-Việt.txt",
}


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_base_tree_and_fixed_timestamps(tmp_path):
    corpus.create_standard_corpus(tmp_path)
    # Stat known paths before reading payloads OR enumerating directories (atime).
    expected = BASE_PATHS | AUX_PATHS | {"manifest.json"}
    for path in [tmp_path, *(tmp_path / name for name in expected)]:
        info = path.stat()
        assert info.st_mtime_ns == FIXED_NS, path
        assert info.st_atime_ns == FIXED_NS, path
    assert {p.relative_to(tmp_path).as_posix() for p in (tmp_path / "set1").rglob("*")} | {
        "set1"
    } == BASE_PATHS
    assert not list((tmp_path / "set1/emptyFolder").iterdir())


def test_jpeg_and_ooxml_are_valid(tmp_path):
    corpus.create_standard_corpus(tmp_path)
    for name in ["set1/2021.JPG", "set1/Study/capture.JPG"]:
        with Image.open(tmp_path / name) as image:
            assert image.format == "JPEG"
            image.load()
            assert image.size == (16, 16)
    with zipfile.ZipFile(tmp_path / "set1/Study/Sample.docx") as document:
        assert document.testzip() is None
        types = ET.fromstring(document.read("[Content_Types].xml"))
        assert any(
            item.get("PartName") == "/word/document.xml"
            and item.get("ContentType")
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
            for item in types
        )
        relationships = ET.fromstring(document.read("_rels/.rels"))
        assert any(
            item.get("Type")
            == "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
            and item.get("Target") == "word/document.xml"
            for item in relationships
        )
        main = ET.fromstring(document.read("word/document.xml"))
        ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        assert main.tag == ns + "document"
        assert main.find(ns + "body") is not None
        assert "Standard forensics test content." in "".join(main.itertext())


def test_auxiliary_encodings_and_nested_zip(tmp_path):
    corpus.create_standard_corpus(tmp_path)
    korean = "가나다"
    for form in ("NFC", "NFD"):
        folder = tmp_path / "auxiliary" / ("korean_" + form.lower())
        (sample,) = folder.iterdir()
        assert sample.stem == unicodedata.normalize(form, korean)
        assert sample.read_text(encoding="utf-8") == "가나다\n"
    assert (tmp_path / "auxiliary/encodings/korean-cp949.txt").read_bytes().decode(
        "cp949"
    ) == "가나다\n"
    assert (tmp_path / "auxiliary/vietnamese/tiếng-Việt.txt").read_text(
        encoding="utf-8"
    ) == "Tiếng Việt\n"
    with zipfile.ZipFile(tmp_path / "auxiliary/double_zip/inner.zip") as nested:
        assert nested.testzip() is None
        assert nested.namelist() == ["nested.txt"]
        assert nested.read("nested.txt") == b"Nested ZIP fixture.\n"
        assert nested.getinfo("nested.txt").date_time == (2021, 1, 11, 11, 30, 58)


def test_manifest_matches_inventory_hashes_and_committed_baseline(tmp_path):
    corpus.create_standard_corpus(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["timestamp_utc"] == "2021-01-11T11:30:59Z"
    assert manifest["timestamp_fields"] == ["atime", "mtime"]
    entries = manifest["entries"]
    assert [entry["path"] for entry in entries] == sorted(entry["path"] for entry in entries)
    assert {entry["path"] for entry in entries} == {
        path.relative_to(tmp_path).as_posix()
        for path in tmp_path.rglob("*")
        if path.name != "manifest.json"
    }
    for entry in entries:
        path = tmp_path / entry["path"]
        assert entry["type"] == ("directory" if path.is_dir() else "file")
        if path.is_file():
            payload = path.read_bytes()
            assert entry["size"] == len(payload)
            assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
    assert manifest == json.loads(
        (ROOT / "data/templates/manifest.json").read_text(encoding="utf-8")
    )


def test_independent_runs_and_reruns_are_identical(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    corpus.create_standard_corpus(first)
    before = snapshot(first)
    corpus.create_standard_corpus(second)
    assert snapshot(second) == before
    # Restore a changed generated file without deleting unrelated data.
    (first / "set1/Study/textsm.txt").write_bytes(b"changed")
    corpus.create_standard_corpus(first)
    assert snapshot(first) == before


def test_unrelated_files_are_refused_before_any_write(tmp_path):
    corpus.create_standard_corpus(tmp_path)
    sentinel = tmp_path / "set1/keep-me.txt"
    sentinel.write_bytes(b"user data")
    before = snapshot(tmp_path)
    with pytest.raises(ValueError, match="Unexpected"):
        corpus.create_standard_corpus(tmp_path)
    assert snapshot(tmp_path) == before


def test_symlink_targets_are_refused_without_touching_destination(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "corpus"
    target.mkdir()
    try:
        (target / "set1").symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        # Directory junctions do not require Windows symlink privileges.
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(target / "set1"), str(outside)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
    with pytest.raises(ValueError, match="link|reparse"):
        corpus.create_standard_corpus(target)
    assert list(outside.iterdir()) == []


def test_cli_output_is_independent_of_working_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(tmp_path / "output")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "output/manifest.json").is_file()
