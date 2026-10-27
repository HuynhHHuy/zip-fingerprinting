"""Deterministic structural hasher generating canonical SHA-256 digests.

Reference:
    Minji Um, Jaehyeok Han, Sangjin Lee.
    "File fingerprinting of the ZIP format for identifying and tracking provenance",
    Forensic Science International: Digital Investigation 39 (2021) 301271.
"""

import hashlib
import json
from typing import Any, Dict, Optional, Union

from zip_fingerprint.schema import FingerprintSchemaV1


def get_canonical_json_bytes(structural_data: Dict[str, Any]) -> bytes:
    """Serialize dictionary into deterministic, sorted canonical JSON bytes."""
    def _normalize(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {str(k): _normalize(v) for k, v in sorted(obj.items(), key=lambda item: str(item[0]))}
        if isinstance(obj, (list, tuple)):
            return [_normalize(item) for item in obj]
        return obj

    normalized = _normalize(structural_data)
    canonical_str = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return canonical_str.encode("utf-8")


def compute_structural_hash(features: Union[Dict[str, Any], FingerprintSchemaV1]) -> str:
    """Generate deterministic SHA-256 digest from canonical structural features.
    
    Forensic Invariance Principle:
    The structural hash isolates the structural fingerprint (high_weight + subsidiary features)
    from file_path and mutable file metadata, ensuring that the same ZIP archive receives
    an identical hash regardless of location on disk, renaming, or environment.
    """
    if isinstance(features, FingerprintSchemaV1):
        target_features = {
            "high_weight": features.high_weight_features.model_dump(),
            "subsidiary": features.subsidiary_features.model_dump(),
        }
    elif isinstance(features, dict):
        if "high_weight" in features and "subsidiary" in features:
            target_features = {
                "high_weight": features["high_weight"],
                "subsidiary": features["subsidiary"],
            }
        else:
            target_features = features
    else:
        raise TypeError(f"Unsupported features type: {type(features)}")

    return hashlib.sha256(get_canonical_json_bytes(target_features)).hexdigest()


def build_canonical_fingerprint(
    extracted_features: Dict[str, Any],
    sha256_content: Optional[str] = None,
) -> FingerprintSchemaV1:
    """Build a validated FingerprintSchemaV1 with computed deterministic structural hash."""
    structural_hash = compute_structural_hash(extracted_features)
    return FingerprintSchemaV1.from_features(
        features=extracted_features,
        structural_hash=structural_hash,
        sha256_content=sha256_content,
    )
