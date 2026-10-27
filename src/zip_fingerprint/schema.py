"""Schema definitions for canonical JSON fingerprint export.

Reference:
    Minji Um, Jaehyeok Han, Sangjin Lee.
    "File fingerprinting of the ZIP format for identifying and tracking provenance",
    Forensic Science International: Digital Investigation 39 (2021) 301271.
"""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field


class FileMetadata(BaseModel):
    """File metadata of the analyzed ZIP archive."""
    model_config = ConfigDict(extra="ignore")

    file_path: str = Field(description="Path or identifier of the archive")
    file_size: int = Field(ge=0, description="Total archive size in bytes")
    total_entries: int = Field(ge=0, description="Total central directory entries")
    total_files: int = Field(ge=0, description="Count of standard file entries")
    total_folders: int = Field(ge=0, description="Count of directory entries")
    sha256_content: Optional[str] = Field(default=None, description="SHA-256 hash of entire archive binary")


class HighWeightFeatures(BaseModel):
    """Algorithm 1 & 2 High-weight structural forensic features."""
    model_config = ConfigDict(extra="ignore")

    host_os: Optional[int] = Field(default=None, description="Host OS code from version_made_by (0: Windows, 3: Unix/macOS/Ubuntu)")
    has_consistent_host_os: bool = Field(default=True, description="True if all entries share the same Host OS")
    data_descriptor_present: bool = Field(default=False, description="True if any LFH has data descriptor")
    local_extra_field_ids: List[int] = Field(default_factory=list, description="Sorted unique extra field IDs in LFH")
    local_extra_field_lengths: Dict[str, List[int]] = Field(default_factory=dict, description="Lengths of extra fields in LFH by ID")
    local_extra_field_sequence: List[int] = Field(default_factory=list, description="Original sequence of extra field IDs in LFH")
    central_extra_field_ids: List[int] = Field(default_factory=list, description="Sorted unique extra field IDs in CDH")
    central_extra_field_lengths: Dict[str, List[int]] = Field(default_factory=dict, description="Lengths of extra fields in CDH by ID")
    central_extra_field_sequence: List[int] = Field(default_factory=list, description="Original sequence of extra field IDs in CDH")


class SubsidiaryFeatures(BaseModel):
    """Algorithm 3 Subsidiary forensic contextual features."""
    model_config = ConfigDict(extra="ignore")

    nanosecond_pattern: Optional[str] = Field(default=None, description="NTFS 0x000A nano pattern ('fff0000', 'fffffff', '0000000')")
    has_macosx_folder: bool = Field(default=False, description="Presence of __MACOSX resource fork folder")
    unicode_normalization: str = Field(default="ASCII", description="Unicode normalization form ('NFC', 'NFD', 'ASCII')")
    filename_encoding: str = Field(default="DEFAULT", description="Filename encoding ('UTF-8' or 'DEFAULT')")
    uid_gid: Optional[Tuple[int, int]] = Field(default=None, description="Extracted (UID, GID) tuple from 0x7875 or 0x5855")
    double_zipping_behavior: Optional[bool] = Field(default=None, description="Compression applied to inner .zip files")
    root_folder_header_exists: bool = Field(default=True, description="Explicit header for root directory")
    empty_folder_headers_exist: bool = Field(default=True, description="Explicit headers for empty directories")
    timezone_offset_minutes: Optional[float] = Field(default=None, description="Timezone offset calculated between DOS and UTC timestamp")
    is_alphabetical_order: bool = Field(default=True, description="Entries ordered alphabetically by filename")


class FingerprintSchemaV1(BaseModel):
    """Canonical representation of a ZIP file structural fingerprint (v1.0.0)."""
    model_config = ConfigDict(extra="ignore")

    schema_version: str = Field(default="1.0.0", description="Schema specification version")
    file_metadata: FileMetadata
    high_weight_features: HighWeightFeatures
    subsidiary_features: SubsidiaryFeatures
    structural_hash: str = Field(description="Deterministic SHA-256 digest of structural features")

    @classmethod
    def from_features(
        cls,
        features: Dict[str, Any],
        structural_hash: str,
        sha256_content: Optional[str] = None,
    ) -> "FingerprintSchemaV1":
        """Factory constructor converting extractor output dict and hash into validated model."""
        summary = dict(features.get("summary", {}))
        if sha256_content:
            summary["sha256_content"] = sha256_content

        # Convert int keys in lengths to str for JSON / dict compatibility
        hw = dict(features.get("high_weight", {}))
        for key in ["local_extra_field_lengths", "central_extra_field_lengths"]:
            if key in hw and isinstance(hw[key], dict):
                hw[key] = {str(k): v for k, v in hw[key].items()}

        return cls(
            schema_version="1.0.0",
            file_metadata=FileMetadata(**summary),
            high_weight_features=HighWeightFeatures(**hw),
            subsidiary_features=SubsidiaryFeatures(**features.get("subsidiary", {})),
            structural_hash=structural_hash,
        )
