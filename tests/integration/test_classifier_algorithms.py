"""Exercise Figures 7–8 with independent Table 6/7 observations."""

from copy import deepcopy
import json

import pytest

from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.parser import ZipBinaryParser


def features(host=0, local=(), central=(0x000A,), descriptor=False, lengths=None, **signals):
    """Use the extractor's wire format, including integer length-map keys."""
    local_lengths, central_lengths = lengths or ({}, {})
    return {
        "high_weight": {
            "host_os": host,
            "has_consistent_host_os": True,
            "data_descriptor_present": descriptor,
            "local_extra_field_ids": list(local),
            "central_extra_field_ids": sorted(central),
            "central_extra_field_sequence": list(central),
            "local_extra_field_lengths": local_lengths,
            "central_extra_field_lengths": central_lengths,
        },
        "subsidiary": signals,
        "summary": {"total_entries": 3},
    }


def environments(candidates):
    return [(candidate.target_os, candidate.application) for candidate in candidates]


# Explicit profiles: deliberately do not derive observations from rules.py.
@pytest.mark.parametrize(
    "expected,observed",
    [
        (
            ("Windows", "WinRAR"),
            features(
                local=(0x7075,),
                central=(0x000A, 0x7075),
                nanosecond_pattern="fffffff",
                double_zipping="STORED",
            ),
        ),
        (
            ("Windows", "WinZip"),
            features(
                local=(0x7075,),
                central=(0x7075, 0x000A),
                nanosecond_pattern="fff0000",
                double_zipping="RECOMPRESSED",
            ),
        ),
        (
            ("Windows", "7-Zip"),
            features(nanosecond_pattern="fffffff", double_zipping="RECOMPRESSED"),
        ),
        (
            ("Windows", "Bandizip"),
            features(
                local=(0x7075,),
                central=(0x000A, 0x7075),
                nanosecond_pattern="fffffff",
                double_zipping="RECOMPRESSED",
            ),
        ),
        (("Windows", "Compressed folder"), features(central=())),
        (("macOS", "WinZip"), features(host=3, central=())),
        (("macOS", "Bandizip"), features(host=3, local=(0x5855,), central=(0x5855,))),
        (
            ("macOS", "Compress"),
            features(
                host=3,
                local=(0x5455, 0x7875),
                central=(0x5455, 0x7875),
                descriptor=True,
                lengths=({0x5455: [13]}, {0x5455: [13]}),
                has_macosx_folder=True,
                unicode_normalization="NFD",
                uid=501,
                gid=20,
            ),
        ),
        (
            ("macOS", "zip"),
            features(
                host=3,
                local=(0x5455, 0x7875),
                central=(0x5455, 0x7875),
                lengths=({0x5455: [9]}, {0x5455: [5]}),
                unicode_normalization="NFD",
                uid=501,
                gid=20,
                double_zipping="STORED",
            ),
        ),
        (("Ubuntu", "7-Zip"), features(host=3)),
        (
            ("Ubuntu", "Compress"),
            features(
                host=3,
                local=(0x5455, 0x7875),
                central=(0x5455, 0x7875),
                descriptor=True,
                lengths=({0x5455: [13]}, {0x5455: [13]}),
                has_macosx_folder=False,
                unicode_normalization="NFC",
                uid=1000,
                gid=1000,
            ),
        ),
        (
            ("Ubuntu", "zip"),
            features(
                host=3,
                local=(0x5455, 0x7875),
                central=(0x5455, 0x7875),
                lengths=({0x5455: [9]}, {0x5455: [5]}),
                unicode_normalization="NFC",
                uid=1000,
                gid=1000,
                double_zipping="STORED",
            ),
        ),
    ],
)
def test_all_twelve_theoretical_profiles(expected, observed):
    result = AutomatedClassifier().classify(observed)
    assert environments(result)[0] == expected
    # The ASCII Windows 7-Zip profile cannot exclude Bandizip without Unicode fields.
    if expected == ("Windows", "7-Zip"):
        assert result[0].confidence == result[1].confidence
        assert environments(result)[:2] == [("Windows", "7-Zip"), ("Windows", "Bandizip")]
    else:
        assert len(result) == 1 or result[0].confidence > result[1].confidence
    assert result[0].matched_rules
    assert all(0 <= item.confidence <= 1 for item in result)


def test_algorithm_1_uses_descriptor_and_both_timestamp_lengths():
    classifier = AutomatedClassifier()
    observed = features(
        host=3,
        local=(0x5455, 0x7875),
        central=(0x5455, 0x7875),
        descriptor=True,
        lengths=({0x5455: [13]}, {0x5455: [13]}),
    )
    assert [rule.application for rule in classifier.estimate_program_1(observed)] == [
        "Compress",
        "Compress",
    ]
    observed["high_weight"]["central_extra_field_lengths"][0x5455] = [5]
    assert classifier.estimate_program_1(observed) == []
    observed["high_weight"]["central_extra_field_lengths"][0x5455] = [13]
    observed["high_weight"]["data_descriptor_present"] = False
    assert classifier.estimate_program_1(observed) == []


@pytest.mark.parametrize(
    "host,expected", [(0, ["Windows"]), (3, ["macOS", "Ubuntu"]), (19, []), (None, [])]
)
def test_algorithm_2_host_os(host, expected):
    assert AutomatedClassifier().estimate_program_2(features(host=host)) == expected


def test_unique_high_weight_match_skips_subsidiary(monkeypatch):
    classifier = AutomatedClassifier()

    def unexpected(*args):
        pytest.fail("A unique high-weight match must not invoke Algorithm 3")

    monkeypatch.setattr(classifier, "estimate_program_3", unexpected)
    (candidate,) = classifier.classify(features(host=3, central=()))
    assert (candidate.target_os, candidate.application) == ("macOS", "WinZip")
    assert candidate.weight_tier == "HIGH"
    assert candidate.confidence == 1.0


def test_algorithm_3_records_matches_conflicts_and_preserves_candidates():
    classifier = AutomatedClassifier()
    observed = features(
        local=(0x7075,),
        central=(0x7075, 0x000A),
        nanosecond_pattern="fff0000",
        double_zipping="RECOMPRESSED",
    )
    candidates = classifier.estimate_program_1(observed)
    candidates = [rule for rule in candidates if rule.target_os == "Windows"]
    result = classifier.estimate_program_3(observed, candidates)
    assert environments(result) == [
        ("Windows", "WinZip"),
        ("Windows", "Bandizip"),
        ("Windows", "WinRAR"),
    ]
    assert all(item.weight_tier == "SUBSIDIARY" and item.confidence < 1 for item in result)
    assert any("nanosecond_pattern" in match for match in result[0].matched_rules)
    assert any("conflict" in note.lower() for note in result[-1].notes)


def test_unknown_signals_retain_ties_and_do_not_mutate_input():
    observed = features(
        nanosecond_pattern="N/A",
        unicode_normalization="ASCII",
        filename_encoding="DEFAULT",
        double_zipping="NO_NESTED_ZIP",
        root_folder_header_exists=None,
        uid=None,
        gid=None,
    )
    before = deepcopy(observed)
    result = AutomatedClassifier().classify(observed)
    assert observed == before
    assert len(result) == 4
    assert len({item.confidence for item in result}) == 1
    assert any("ambiguous" in note.lower() for note in result[0].notes)


@pytest.mark.parametrize(
    "observed",
    [
        {},
        {"high_weight": {}},
        features(host=99),
        features(central=(0xBEEF,)),
        features(local=(0x7075,), central=()),
    ],
)
def test_missing_or_unsupported_structural_evidence_returns_no_candidates(observed):
    assert AutomatedClassifier().classify(observed) == []


def test_empty_and_mixed_host_archives_are_not_classified_as_single_source():
    observed = features(central=())
    observed["summary"]["total_entries"] = 0
    assert AutomatedClassifier().classify(observed) == []
    observed["summary"]["total_entries"] = 3
    observed["high_weight"]["has_consistent_host_os"] = False
    assert AutomatedClassifier().classify(observed) == []


def test_json_roundtrip_of_extra_field_length_keys():
    observed = features(
        host=3,
        local=(0x5455, 0x7875),
        central=(0x5455, 0x7875),
        lengths=({0x5455: [9]}, {0x5455: [5]}),
        uid=501,
        gid=20,
    )
    classifier = AutomatedClassifier()
    assert classifier.classify(observed) == classifier.classify(json.loads(json.dumps(observed)))


def test_parser_extractor_classifier_pipeline(tmp_path, minimal_zip_bytes):
    archive_path = tmp_path / "minimal.zip"
    archive_path.write_bytes(minimal_zip_bytes)
    with ZipBinaryParser(archive_path) as parser:
        observed = StructuralFeatureExtractor(parser.parse()).extract()
    result = AutomatedClassifier().classify(observed)
    assert environments(result) == [("Windows", "Compressed folder")]
    assert result[0].weight_tier == "HIGH"


def test_low_weight_cp949_cannot_override_unix_host_os():
    observed = features(
        host=3,
        local=(0x5455, 0x7875),
        central=(0x5455, 0x7875),
        lengths=({0x5455: [9]}, {0x5455: [5]}),
        filename_encoding="CP949",
    )
    result = AutomatedClassifier().classify(observed)
    assert {item.target_os for item in result} == {"macOS", "Ubuntu"}
    assert all(
        any("Conflicting filename_encoding" in note for note in item.notes) for item in result
    )
    assert all(
        any("observed CP949, expected UTF-8" in note for note in item.notes) for item in result
    )


def test_zero_nanoseconds_and_folder_order_are_reported_as_evidence():
    observed = features(
        nanosecond_pattern="0000000",
        filename_encoding="CP949",
        root_folder_header_exists=True,
        is_alphabetical_order=False,
    )
    result = AutomatedClassifier().classify(observed)
    for candidate in result:
        assert any("root_folder_header_exists=True" in match for match in candidate.matched_rules)
        assert any("filename_encoding=CP949" in match for match in candidate.matched_rules)
        assert any("Conflicting nanosecond_pattern" in note for note in candidate.notes)
        assert any("Conflicting is_alphabetical_order" in note for note in candidate.notes)
        # Order/encoding/folder support weighs 6, conflicting nano/order weighs 4.
        assert candidate.confidence == pytest.approx(0.598)


def test_no_comparable_subsidiary_evidence_has_neutral_score():
    observed = features()
    observed["high_weight"].pop("central_extra_field_sequence")
    result = AutomatedClassifier().classify(observed)
    assert len(result) == 4
    assert all(item.confidence == 0.5 for item in result)
    assert all(any("No comparable" in note for note in item.notes) for item in result)


@pytest.mark.parametrize(
    "key,value",
    [
        ("host_os", True),
        ("host_os", "0"),
        ("has_consistent_host_os", False),
        ("data_descriptor_present", None),
        ("local_extra_field_ids", None),
        ("central_extra_field_ids", ["10"]),
    ],
)
def test_incomplete_or_malformed_high_weight_values_are_not_guessed(key, value):
    observed = features()
    observed["high_weight"][key] = value
    assert AutomatedClassifier().classify(observed) == []


@pytest.mark.parametrize("lengths", [({}, {}), ({0x5455: [9, 13]}, {0x5455: [5]}), (None, {})])
def test_missing_mixed_or_malformed_timestamp_lengths_are_not_guessed(lengths):
    observed = features(host=3, local=(0x5455, 0x7875), central=(0x5455, 0x7875), lengths=lengths)
    assert AutomatedClassifier().classify(observed) == []


def test_non_ascii_7zip_is_distinguishable_without_claiming_high_tier_certainty():
    observed = features(
        unicode_normalization="NFC",
        filename_encoding="UTF-8",
        nanosecond_pattern="fffffff",
        double_zipping="RECOMPRESSED",
    )
    result = AutomatedClassifier().classify(observed)
    assert environments(result)[0] == ("Windows", "7-Zip")
    assert result[0].confidence > result[1].confidence
    assert result[0].weight_tier == "SUBSIDIARY"
    assert len(result) == 4  # Subsidiary evidence ranks; it does not erase candidates.
    assert any("unicode_extra_field_variant" in match for match in result[0].matched_rules)
