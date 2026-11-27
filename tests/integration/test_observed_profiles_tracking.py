"""Tracker and classifier with an explicit rule set; synthetic archives, not native evidence.

The S6 shape mirrors what Bandizip 7.47 wrote when deleting from a 7-Zip archive
(docs/evaluation/sw2-screening-2026-11-26.md); the bytes here are built by hand.
"""

import pytest

from tests.integration.test_provenance_tracking import (
    Entry,
    ntfs,
    parse,
    unicode_path,
    win_7zip,
    win_bandizip_unicode,
    win_compressed_folder,
    win_winrar,
)
from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.observed_rules import get_observed_rules
from zip_fingerprint.provenance import ProvenanceTracker
from zip_fingerprint.rules import get_all_rules

REWRITE = ("Windows", "Bandizip 7.47 (rewrite, observed)")
UNICODE_NAMES = ["tieng-viet-ệ.txt", "가나다.txt"]


def bandizip_rewrite(name: str) -> Entry:
    if name.isascii():
        return Entry(name)
    return Entry(name, local=[unicode_path(name)], central=[unicode_path(name)])


def s6_shape():
    return [bandizip_rewrite("keep.txt")] + [bandizip_rewrite(name) for name in UNICODE_NAMES]


def with_observed():
    return get_all_rules() + get_observed_rules()


ENTRY_SETS = {
    "7zip": [win_7zip("a.txt"), win_7zip("b.txt")],
    "winrar_unicode": [win_winrar("a.txt"), win_winrar(UNICODE_NAMES[0])],
    "case1_7zip_winrar": [win_7zip("a.txt"), win_winrar(UNICODE_NAMES[0])],
    "case2_discrepancy": [Entry("a.txt", local=[unicode_path("aé")], central=[ntfs()])],
    "s6_shape": s6_shape(),
}


@pytest.mark.parametrize("name", sorted(ENTRY_SETS))
def test_default_output_is_unchanged(name):
    archive = parse(ENTRY_SETS[name])
    default = ProvenanceTracker(archive).analyze().to_dict()
    explicit = ProvenanceTracker(archive, rules=get_all_rules()).analyze().to_dict()
    assert "catalogs_used" not in default
    assert default == explicit


def test_s6_shape_is_case1_with_paper_catalog():
    report = ProvenanceTracker(parse(s6_shape())).analyze()
    assert report.case1_detected is True
    suspects = {(s.target_os, s.application, s.role) for s in report.suspected_applications}
    assert ("Windows", "Compressed folder", "ORIGINAL_CREATOR_SUSPECT") in suspects


def test_s6_shape_is_single_group_with_observed_profiles():
    report = ProvenanceTracker(parse(s6_shape()), rules=with_observed()).analyze()
    assert report.case1_detected is False
    assert len(report.groups) == 1
    assert report.groups[0].candidates == [REWRITE]
    data = report.to_dict()
    assert data["catalogs_used"] == ["paper", "observed"]
    assert data["groups"][0]["candidates"][0]["catalog"] == "observed"
    for suspect in data["suspected_applications"]:
        assert suspect["catalog"] in ("paper", "observed")


def test_observed_profiles_keep_real_case1():
    entries = [
        Entry("keep.txt", central=[ntfs()]),
        win_bandizip_unicode(UNICODE_NAMES[0]),
        win_compressed_folder("added.txt"),
    ]
    report = ProvenanceTracker(parse(entries), rules=with_observed()).analyze()
    assert report.case1_detected is True


def test_classifier_default_rules_unchanged():
    assert AutomatedClassifier()._rules == get_all_rules()


def test_observed_profiles_leave_explorer_ascii_archives_ambiguous():
    # An Explorer-created ASCII archive has no extra fields, exactly like a Bandizip rewrite:
    # both stay candidates, labelled by catalog, and neither is reported as Case 1.
    entries = [win_compressed_folder("a.txt"), win_compressed_folder("b.txt")]
    report = ProvenanceTracker(parse(entries), rules=with_observed()).analyze()
    assert report.case1_detected is False
    assert report.groups[0].candidates == [("Windows", "Compressed folder"), REWRITE]
    catalogs = {s["application"]: s["catalog"] for s in report.to_dict()["suspected_applications"]}
    assert catalogs == {"Compressed folder": "paper", REWRITE[1]: "observed"}
