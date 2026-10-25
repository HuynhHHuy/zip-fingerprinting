"""Unit tests for structural hasher."""

from zip_fingerprint.hasher import compute_structural_hash


def test_compute_structural_hash_deterministic() -> None:
    data1 = {"b": 2, "a": 1}
    data2 = {"a": 1, "b": 2}
    hash1 = compute_structural_hash(data1)
    hash2 = compute_structural_hash(data2)
    assert hash1 == hash2
    assert len(hash1) == 64

