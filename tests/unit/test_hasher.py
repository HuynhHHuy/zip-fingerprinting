"""Unit tests for structural hasher and canonical schema."""

import json
import pytest

from zip_fingerprint.hasher import (
    compute_structural_hash,
    get_canonical_json_bytes,
    build_canonical_fingerprint,
)
from zip_fingerprint.schema import (
    FingerprintSchemaV1,
    FileMetadata,
    HighWeightFeatures,
    SubsidiaryFeatures,
)


@pytest.fixture
def sample_features() -> dict:
    """Fixture providing realistic extracted features."""
    return {
        "high_weight": {
            "host_os": 0,
            "has_consistent_host_os": True,
            "data_descriptor_present": False,
            "local_extra_field_ids": [0x7075],
            "local_extra_field_lengths": {"28789": [24]},
            "local_extra_field_sequence": [0x7075],
            "central_extra_field_ids": [0x000A, 0x7075],
            "central_extra_field_lengths": {"10": [32], "28789": [24]},
            "central_extra_field_sequence": [0x000A, 0x7075],
        },
        "subsidiary": {
            "nanosecond_pattern": "fffffff",
            "has_macosx_folder": False,
            "unicode_normalization": "NFC",
            "filename_encoding": "UTF-8",
            "uid_gid": None,
            "double_zipping_behavior": False,
            "root_folder_header_exists": True,
            "empty_folder_headers_exist": True,
            "timezone_offset_minutes": 540.0,
            "is_alphabetical_order": True,
        },
        "summary": {
            "file_path": "/var/tmp/sample.zip",
            "file_size": 12450,
            "total_entries": 5,
            "total_files": 4,
            "total_folders": 1,
        },
    }


def test_compute_structural_hash_deterministic(sample_features: dict) -> None:
    """Test that 100 consecutive hash calculations on identical data yield identical SHA-256."""
    first_hash = compute_structural_hash(sample_features)
    assert len(first_hash) == 64

    for _ in range(100):
        current_hash = compute_structural_hash(sample_features)
        assert current_hash == first_hash


def test_key_ordering_invariance() -> None:
    """Test that key insertion order does not affect canonical hash."""
    data_a = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    data_b = {"c": {"x": 10, "y": 20}, "a": 1, "b": 2}

    assert compute_structural_hash(data_a) == compute_structural_hash(data_b)


def test_file_path_invariance(sample_features: dict) -> None:
    """Test that changing file_path or summary does NOT change structural hash."""
    base_hash = compute_structural_hash(sample_features)

    modified_features = dict(sample_features)
    modified_features["summary"] = {
        "file_path": "C:\\Windows\\System32\\other.zip",
        "file_size": 999999,
        "total_entries": 5,
        "total_files": 4,
        "total_folders": 1,
    }

    assert compute_structural_hash(modified_features) == base_hash


def test_structural_change_alters_hash(sample_features: dict) -> None:
    """Test that changes to structural features produce distinct hashes."""
    base_hash = compute_structural_hash(sample_features)

    # Change nanosecond pattern from fffffff to fff0000 (WinZip)
    changed = json.loads(json.dumps(sample_features))
    changed["subsidiary"]["nanosecond_pattern"] = "fff0000"
    winzip_hash = compute_structural_hash(changed)

    assert winzip_hash != base_hash
    assert len(winzip_hash) == 64


def test_build_canonical_fingerprint(sample_features: dict) -> None:
    """Test constructing a validated FingerprintSchemaV1 object."""
    fp = build_canonical_fingerprint(
        extracted_features=sample_features,
        sha256_content="a" * 64,
    )

    assert isinstance(fp, FingerprintSchemaV1)
    assert fp.schema_version == "1.0.0"
    assert fp.file_metadata.file_path == "/var/tmp/sample.zip"
    assert fp.file_metadata.sha256_content == "a" * 64
    assert fp.high_weight_features.host_os == 0
    assert fp.subsidiary_features.nanosecond_pattern == "fffffff"
    assert len(fp.structural_hash) == 64

    # Verify model hash matches direct hash
    assert fp.structural_hash == compute_structural_hash(sample_features)
    assert compute_structural_hash(fp) == fp.structural_hash

    # Verify JSON serialization and round-trip parsing
    json_str = fp.model_dump_json()
    reparsed = FingerprintSchemaV1.model_validate_json(json_str)
    assert reparsed.structural_hash == fp.structural_hash


def test_canonical_json_bytes_compact() -> None:
    """Test that canonical JSON has no whitespace padding."""
    raw = {"z": 1, "a": [2, 3]}
    b = get_canonical_json_bytes(raw)
    assert b == b'{"a":[2,3],"z":1}'


def test_compute_structural_hash_invalid_type() -> None:
    """Test that passing unsupported type raises TypeError."""
    with pytest.raises(TypeError, match="Unsupported features type"):
        compute_structural_hash([1, 2, 3])  # type: ignore[arg-type]

