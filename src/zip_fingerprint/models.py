"""Data models representing ZIP binary structures and forensic fingerprints."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class ExtraFieldBlock:
    """Represents a single raw extra field record: (Header ID, Data Size, Data)."""
    header_id: int
    data_size: int
    raw_data: bytes


@dataclass
class LocalFileHeaderRecord:
    """Local File Header record parsed from raw binary."""
    offset: int
    extract_version: int
    gp_bit_flag: int
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    file_name_length: int
    extra_field_length: int
    file_name: str
    extra_fields: List[ExtraFieldBlock] = field(default_factory=list)
    has_data_descriptor: bool = False


@dataclass
class CentralDirectoryHeaderRecord:
    """Central Directory Header record parsed from raw binary."""
    offset: int
    version_made_by: int
    extract_version: int
    gp_bit_flag: int
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    file_name_length: int
    extra_field_length: int
    file_comment_length: int
    disk_number_start: int
    internal_file_attributes: int
    external_file_attributes: int
    local_header_offset: int
    file_name: str
    extra_fields: List[ExtraFieldBlock] = field(default_factory=list)
    file_comment: bytes = b""


@dataclass
class EndOfCentralDirectoryRecord:
    """End of Central Directory (EOCD) record."""
    offset: int
    disk_number: int
    cd_start_disk: int
    num_entries_this_disk: int
    total_entries: int
    cd_size: int
    cd_start_offset: int
    comment_length: int
    comment: bytes = b""


@dataclass
class ZipArchiveRecord:
    """Container holding full raw structure of a ZIP archive."""
    file_path: str
    file_size: int
    eocd: EndOfCentralDirectoryRecord
    central_directory_headers: List[CentralDirectoryHeaderRecord] = field(default_factory=list)
    local_file_headers: List[LocalFileHeaderRecord] = field(default_factory=list)

    def has_data_descriptor(self) -> bool:
        """Check if any local file header has a data descriptor (Um et al. 2021 Section 3.3.2)."""
        return any(lfh.has_data_descriptor for lfh in self.local_file_headers)


@dataclass
class CandidateEnvironment:
    """Classification candidate environment result."""
    target_os: str
    application: str
    confidence: float
    matched_rules: List[str] = field(default_factory=list)
    weight_tier: str = "HIGH"  # HIGH or SUBSIDIARY
    notes: List[str] = field(default_factory=list)

