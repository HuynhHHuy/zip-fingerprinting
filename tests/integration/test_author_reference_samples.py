"""Author reference samples (PH0-REF-002 / #17).

The manifest and verification tests run offline. Tests on the real samples need the
bytes fetched by ``scripts/fetch_author_samples.py`` (or AUTHOR_PKZIP_SAMPLES pointing
to a folder with the same layout) and are skipped otherwise: the bytes are not in Git.
"""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data" / "reference" / "author_pkzip" / "manifest.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fetch = _load("fetch_author_samples", ROOT / "scripts" / "fetch_author_samples.py")
analyze = _load("analyze_author_samples", ROOT / "experiments" / "analyze_author_samples.py")

ALLOWED = {
    "Windows": {"7-Zip", "Bandizip", "WinRAR", "WinZip", "Compressed folder"},
    "Ubuntu": {"7-Zip", "zip", "Compress"},
    "macOS": {"Bandizip", "WinZip", "zip", "Compress"},
}


@pytest.fixture(scope="module")
def manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _samples_dir() -> Path:
    override = os.environ.get("AUTHOR_PKZIP_SAMPLES")
    return Path(override) if override else fetch.DEFAULT_DEST


def _sample(data: bytes, **overrides):
    sample = {
        "id": "x",
        "path": "sample/x.zip",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1_git": fetch.git_blob_id(data),
        "label": {"os": "Windows", "application": "Compressed folder"},
        "label_basis": "filename",
    }
    sample.update(overrides)
    return sample


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("set1/2021.JPG", b"jpeg")
        zf.writestr("set1/emptyFolder/", b"")
    return buf.getvalue()


def test_manifest_describes_archive_and_labels_honestly(manifest):
    assert manifest["source"]["snapshot"].startswith("swh:1:snp:")
    assert manifest["source"]["license"] is None
    # label_verified rests on the recorded team decision, not on the file names alone.
    assert manifest["label_decision"]["issue"] == 17
    samples = manifest["samples"]
    assert len(samples) == 17
    assert len({s["sha256"] for s in samples}) == 17
    assert len({s["id"] for s in samples}) == 17
    for s in samples:
        assert s["path"].startswith("sample/") and s["path"].endswith(".zip")
        assert s["swhid"] == f"swh:1:cnt:{s['sha1_git']}"
        assert s["label_basis"] == "author_declared_filename"
        assert s["label_verified"] is True
        assert s["label"]["application"] in ALLOWED[s["label"]["os"]]


def test_manifest_covers_paper_tool_matrix(manifest):
    seen = {(s["label"]["os"], s["label"]["application"]) for s in manifest["samples"]}
    expected = {(os_name, app) for os_name, apps in ALLOWED.items() for app in apps}
    assert seen == expected


def test_git_blob_id_matches_git():
    assert fetch.git_blob_id(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"


@pytest.mark.parametrize(
    "field, value",
    [("size", 1), ("sha1_git", "0" * 40), ("sha256", "0" * 64)],
)
def test_verify_rejects_any_mismatch(field, value):
    data = b"payload"
    with pytest.raises(fetch.VerificationError):
        fetch.verify(_sample(data, **{field: value}), data)


def test_fetch_reuses_verified_cache_without_network(tmp_path, monkeypatch):
    data = b"cached bytes"
    sample = _sample(data)
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample" / "x.zip").write_bytes(data)

    def no_network(*_args, **_kwargs):
        raise AssertionError("network used")

    monkeypatch.setattr(fetch, "download", no_network)
    assert fetch.fetch({"samples": [sample]}, tmp_path) == [tmp_path / "sample" / "x.zip"]


def test_fetch_refuses_tampered_download(tmp_path, monkeypatch):
    sample = _sample(b"expected")
    monkeypatch.setattr(fetch, "download", lambda _sha: b"tampered")
    with pytest.raises(fetch.VerificationError):
        fetch.fetch({"samples": [sample]}, tmp_path)
    assert not (tmp_path / "sample" / "x.zip").exists()


def test_analysis_reports_checksum_mismatch_without_parsing():
    sample = _sample(b"zip", sha256="0" * 64)
    assert analyze.analyze_sample(sample, b"zip")["status"] == "checksum_mismatch"


def test_paper_checks_judge_labels_not_classifier():
    data = _zip_bytes()
    record = analyze.analyze_sample(_sample(data), data)
    checks = {c["check"]: c for c in record["paper_checks"]}
    # zipfile writes the folder entry but no root header: matches Compressed folder.
    assert checks["root_folder_header"]["status"] == "consistent"
    assert checks["data_descriptor"]["status"] == "not_applicable"

    relabelled = _sample(data, label={"os": "Windows", "application": "WinRAR"})
    record = analyze.analyze_sample(relabelled, data)
    assert "root_folder_header" in record["paper_inconsistencies"]


def test_run_marks_missing_samples(tmp_path, manifest):
    report = analyze.run(MANIFEST, tmp_path)
    assert report["summary"]["parsed"] == 0
    assert all(r["status"] == "missing" for r in report["samples"])
    assert len(report["samples"]) == len(manifest["samples"])


def test_real_samples_parse_and_match_paper_structure(manifest):
    samples_dir = _samples_dir()
    if not all((samples_dir / s["path"]).is_file() for s in manifest["samples"]):
        pytest.skip("Requires author samples: run scripts/fetch_author_samples.py")

    report = analyze.run(MANIFEST, samples_dir)

    assert report["summary"]["parsed"] == 17
    for record in report["samples"]:
        assert record["paper_inconsistencies"] == [], record["id"]
