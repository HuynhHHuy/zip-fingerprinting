"""Schema definitions for canonical JSON fingerprint export."""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class FingerprintSchemaV1(BaseModel):
    """Canonical representation of a ZIP file structural fingerprint."""
    schema_version: str = "1.0.0"
    file_metadata: Dict[str, Any]
    high_weight_features: Dict[str, Any]
    subsidiary_features: Dict[str, Any]
    structural_hash: str

