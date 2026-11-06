"""Boundary and temporal semantics of the Table 8 analyzer."""

from datetime import datetime, timedelta, timezone

import pytest

from zip_fingerprint.decompression import DecompressionAnalyzer


def test_lookup_accepts_table_notation_and_keeps_ties():
    analyzer = DecompressionAnalyzer()
    assert analyzer.identify_decompressor(" r e e r ", "file", "0x5855") == ["7-Zip"]
    assert analyzer.evaluate_bmac_pattern("ERRR", "Contains file(s)", "0x000A") == [
        "WinZip",
        "Bandizip",
    ]
    assert analyzer.evaluate_bmac_pattern("HHHR", "Empty", "None") == ["WinZip"]
    assert analyzer.evaluate_bmac_pattern("RRRR", "No header", "N/A") == [
        "WinRAR",
        "WinZip",
        "7-Zip",
        "Bandizip",
        "Compressed folder",
    ]
    result = analyzer.identify_decompressor("RHRR", "file")
    result.clear()
    assert analyzer.identify_decompressor("RHRR", "file") == ["WinRAR", "7-Zip", "Bandizip"]


@pytest.mark.parametrize("pattern", ["", "RHR", "RHHRR", "R?RR", "BMAC"])
def test_malformed_bmac_raises(pattern):
    with pytest.raises(ValueError, match="BMAC"):
        DecompressionAnalyzer().identify_decompressor(pattern, "file")


def test_valid_but_unlisted_patterns_and_headers_have_no_candidates():
    analyzer = DecompressionAnalyzer()
    assert analyzer.identify_decompressor("HHHH", "file") == []
    assert analyzer.identify_decompressor("RHRR", "file", "0xBEEF") == []
    assert analyzer.identify_decompressor("RHRR", "file", 0) == []


@pytest.mark.parametrize(
    "entry_type,header",
    [
        ("unknown", None),
        ("folder_no_header", "0x000A"),
        ("file", "N/A"),
        ("file", "garbage"),
        ("file", -1),
        ("file", 65536),
        ("file", True),
    ],
)
def test_invalid_context_raises(entry_type, header):
    with pytest.raises(ValueError):
        DecompressionAnalyzer().identify_decompressor("RHRR", entry_type, header)


@pytest.mark.parametrize(
    "parent,child,birth,modified,expected",
    [
        (1, 2, 1, 2, []),
        (1, 1, 1, 1, []),
        (2, 1, 1, 2, ["SUBFOLDER_BEFORE_PARENT"]),
        (1, 2, 2, 1, ["CREATION_AFTER_MODIFICATION"]),
        (2, 1, 2, 1, ["CREATION_AFTER_MODIFICATION", "SUBFOLDER_BEFORE_PARENT"]),
    ],
)
def test_time_reversal_strict_comparisons(parent, child, birth, modified, expected):
    origin = datetime(2021, 1, 1)
    times = [origin + timedelta(seconds=value) for value in (parent, child, birth, modified)]
    assert DecompressionAnalyzer().check_time_reversal(*times) == expected


def test_time_reversal_compares_utc_instants_and_skips_missing_pairs():
    analyzer = DecompressionAnalyzer()
    utc = datetime(2021, 1, 1, 0, tzinfo=timezone.utc)
    same = datetime(2021, 1, 1, 7, tzinfo=timezone(timedelta(hours=7)))
    assert analyzer.check_time_reversal(utc, same, same, utc) == []
    # The local clock says 07:00, but it is earlier than 01:00 UTC.
    assert analyzer.check_time_reversal(utc + timedelta(hours=1), same) == [
        "SUBFOLDER_BEFORE_PARENT"
    ]
    assert analyzer.check_time_reversal(creation_time=utc + timedelta(seconds=1), mod_time=utc) == [
        "CREATION_AFTER_MODIFICATION"
    ]
    assert analyzer.check_time_reversal(parent_folder_time=utc) == []
    assert analyzer.check_time_reversal() == []


def test_time_reversal_rejects_mixed_awareness_and_non_datetime_values():
    analyzer = DecompressionAnalyzer()
    with pytest.raises(ValueError, match="timezone"):
        analyzer.check_time_reversal(
            datetime(2021, 1, 1), datetime(2021, 1, 1, tzinfo=timezone.utc)
        )
    with pytest.raises(TypeError, match="datetime"):
        analyzer.check_time_reversal(creation_time=123, mod_time=456)
