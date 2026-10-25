"""Deterministic structural hasher generating canonical SHA-256 digests."""

import hashlib
import json
from typing import Dict, Any


def compute_structural_hash(features: Dict[str, Any]) -> str:
    """Generate deterministic SHA-256 digest from canonical JSON representation."""
    canonical_json = json.dumps(features, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

