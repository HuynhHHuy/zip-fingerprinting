"""Shared catalogue of native provenance samples (Case 1, Case 2, negatives) for #19.

Structure and checksums are checked in CI against the committed evidence manifest. Bytes live
on the evidence prerelease; set ZIP_PROV_NATIVE_SAMPLES to the extracted bundle (or the local
data/modified_samples) to re-run the expected outcomes.
"""

import hashlib
import json
import os
from pathlib import Path

import pytest

from zip_fingerprint.baseline import compare_archives
from zip_fingerprint.observed_rules import get_observed_rules
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceTracker
from zip_fingerprint.rules import get_all_rules

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = ROOT / "data" / "modified_samples" / "catalogue.json"
SAMPLES = Path(os.environ.get("ZIP_PROV_NATIVE_SAMPLES", ROOT / "data" / "modified_samples"))
LABELS = {"case1", "case2", "none"}


def _catalogue():
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


def _manifest(bundle):
    path = ROOT / bundle["manifest"]
    return json.loads(path.read_text(encoding="utf-8"))


def test_catalogue_covers_case1_and_case2_with_distinct_bytes():
    data = _catalogue()
    assert data["schema"] == "provenance-sample-catalogue/v1"
    assert {sample["label"] for sample in data["samples"]} <= LABELS
    distinct = {}
    for sample in data["samples"]:
        distinct.setdefault(sample["label"], set()).add(sample["after"]["sha256"])
    # Distinct bytes, so a deterministic confirmation run does not count twice.
    assert len(distinct["case1"]) >= 2
    assert len(distinct["case2"]) >= 1
    by_id = {sample["id"]: sample for sample in data["samples"]}
    assert len(by_id) == len(data["samples"])
    for sample in data["samples"]:
        if "duplicate_of" in sample:
            original = by_id[sample["duplicate_of"]]
            assert original["after"]["sha256"] == sample["after"]["sha256"]
            assert original["label"] == sample["label"]
    for sample in data["samples"]:
        assert sample["label_basis"]
        assert {"tool", "version"} <= set(sample["sw1"]) and {"tool", "version"} <= set(
            sample["sw2"]
        )
        assert sample["operation"] in {"add", "delete"}
        assert sample["bundle"] in data["bundles"]
        for side in ("before", "after"):
            assert len(sample[side]["sha256"]) == 64
            assert sample[side]["size"] > 0


def test_catalogue_checksums_match_committed_evidence_manifests():
    data = _catalogue()
    for sample in data["samples"]:
        bundle = data["bundles"][sample["bundle"]]
        manifest = _manifest(bundle)
        assert manifest["bundle"]["sha256"] == bundle["sha256"]
        assert manifest["bundle"]["size"] == bundle["size"]
        rows = {row["path"]: row for row in manifest["files"]}
        for side in ("before", "after"):
            row = rows[sample[side]["path"]]
            assert (row["sha256"], row["size"]) == (sample[side]["sha256"], sample[side]["size"])


def _local(sample, side):
    path = SAMPLES / sample[side]["path"]
    if not path.is_file():
        pytest.skip(f"Native sample not available: {path}")
    return path


def _parse(path):
    with ZipBinaryParser(path) as parser:
        return parser.parse()


@pytest.mark.parametrize("index", range(len(_catalogue()["samples"])))
def test_native_bytes_reproduce_expected_outcomes(index):
    sample = _catalogue()["samples"][index]
    before, after = _local(sample, "before"), _local(sample, "after")
    for side, path in (("before", before), ("after", after)):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sample[side]["sha256"]
    expected = sample["expected"]
    comparison = compare_archives(_parse(before), _parse(after))
    assert comparison.rewrite_scope == expected["baseline_rewrite_scope"]
    assert comparison.case2_detected is (sample["label"] == "case2")
    default = ProvenanceTracker(_parse(after)).analyze()
    observed = ProvenanceTracker(_parse(after), rules=get_all_rules() + get_observed_rules())
    observed_report = observed.analyze()
    assert default.case1_detected is expected["tracker_default"]["case1"]
    assert default.case2_detected is expected["tracker_default"]["case2"]
    assert observed_report.case1_detected is expected["tracker_observed_profiles"]["case1"]
    assert observed_report.case2_detected is expected["tracker_observed_profiles"]["case2"]
