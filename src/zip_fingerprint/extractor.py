"""Extract structural forensic features from parsed ZIP archive records.

Reference:
    Minji Um, Jaehyeok Han, Sangjin Lee.
    "File fingerprinting of the ZIP format for identifying and tracking provenance",
    Forensic Science International: Digital Investigation 39 (2021) 301271.
    Section 3: Experiments for identifying file fingerprints.
    Section 4.1: Flowchart (Figure 7) and Algorithms 1, 2, 3 (Figure 8).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import unicodedata

from zip_fingerprint.constants import (
    EXTRA_HEADER_NTFS,
    EXTRA_HEADER_EXTENDED_TS,
    EXTRA_HEADER_UNIX_UID_GID,
    EXTRA_HEADER_UNIX_5855,
    EXTRA_HEADER_UNICODE_PATH,
    NANO_PATTERN_FULL,
    NANO_PATTERN_WINZIP,
    NANO_PATTERN_ZERO,
)
from zip_fingerprint.extra_fields import ExtraFieldParser
from zip_fingerprint.models import CentralDirectoryHeaderRecord, ZipArchiveRecord


def dos_to_datetime(dos_time: int, dos_date: int) -> Optional[datetime]:
    """Decode MS-DOS 32-bit date and time integers into a naive datetime."""
    try:
        second = (dos_time & 0x1F) * 2
        minute = (dos_time >> 5) & 0x3F
        hour = (dos_time >> 11) & 0x1F

        day = dos_date & 0x1F
        month = (dos_date >> 5) & 0x0F
        year = ((dos_date >> 9) & 0x7F) + 1980

        if month < 1 or month > 12 or day < 1 or day > 31:
            return None
        return datetime(year, month, day, min(hour, 23), min(minute, 59), min(second, 59))
    except Exception:
        return None


def detect_unicode_normalization(filenames: List[str]) -> str:
    """Detect Unicode normalization form (NFD on macOS vs NFC on Windows/Ubuntu).
    
    Returns 'NFD', 'NFC', or 'ASCII'.
    """
    has_non_ascii = False
    for name in filenames:
        if not name.isascii():
            has_non_ascii = True
            nfc_form = unicodedata.normalize("NFC", name)
            nfd_form = unicodedata.normalize("NFD", name)
            if nfc_form != nfd_form:
                if name == nfd_form:
                    return "NFD"
                if name == nfc_form:
                    return "NFC"

    return "ASCII" if not has_non_ascii else "NFC"


class StructuralFeatureExtractor:
    """Extracts forensic fingerprint vector from raw ZIP structures."""

    def __init__(self, archive: ZipArchiveRecord):
        self.archive = archive

    def extract(self) -> Dict[str, Any]:
        """Extract high-weight and subsidiary features defined in Um et al. (2021)."""
        cdhs = self.archive.central_directory_headers
        lfhs = self.archive.local_file_headers

        high_weight = self._extract_high_weight_features(cdhs, lfhs)
        subsidiary = self._extract_subsidiary_features(cdhs, lfhs)

        total_entries = len(cdhs)
        total_folders = sum(1 for c in cdhs if c.file_name.endswith("/") or c.external_file_attributes & 0x10)
        total_files = total_entries - total_folders

        return {
            "high_weight": high_weight,
            "subsidiary": subsidiary,
            "summary": {
                "file_path": self.archive.file_path,
                "file_size": self.archive.file_size,
                "total_entries": total_entries,
                "total_files": total_files,
                "total_folders": total_folders,
            },
        }

    def _extract_high_weight_features(
        self,
        cdhs: List[CentralDirectoryHeaderRecord],
        lfhs: List[Any],
    ) -> Dict[str, Any]:
        """Extract High-Weight Features (Algorithm 1: SW and Algorithm 2: OS)."""
        # 1. Data Descriptor presence
        data_descriptor_present = any(lfh.has_data_descriptor for lfh in lfhs)

        # 2. Host OS (Algorithm 2: version_made_by upper byte)
        # 0x00: Windows, 0x03: macOS/Ubuntu
        host_os_list: List[int] = []
        for cdh in cdhs:
            host_os = (cdh.version_made_by >> 8) & 0xFF
            host_os_list.append(host_os)

        primary_host_os = host_os_list[0] if host_os_list else None
        has_consistent_host_os = len(set(host_os_list)) <= 1

        # 3. Local extra fields (Algorithm 1)
        local_extra_ids: List[int] = []
        local_extra_lengths: Dict[int, List[int]] = {}
        local_seq: List[int] = []

        for lfh in lfhs:
            seq_for_entry = [b.header_id for b in lfh.extra_fields]
            if not local_seq and seq_for_entry:
                local_seq = seq_for_entry
            for b in lfh.extra_fields:
                if b.header_id not in local_extra_ids:
                    local_extra_ids.append(b.header_id)
                local_extra_lengths.setdefault(b.header_id, []).append(b.data_size)

        # 4. Central extra fields (Algorithm 1)
        central_extra_ids: List[int] = []
        central_extra_lengths: Dict[int, List[int]] = {}
        central_seq: List[int] = []

        for cdh in cdhs:
            seq_for_entry = [b.header_id for b in cdh.extra_fields]
            if not central_seq and seq_for_entry:
                central_seq = seq_for_entry
            for b in cdh.extra_fields:
                if b.header_id not in central_extra_ids:
                    central_extra_ids.append(b.header_id)
                central_extra_lengths.setdefault(b.header_id, []).append(b.data_size)

        return {
            "host_os": primary_host_os,
            "has_consistent_host_os": has_consistent_host_os,
            "data_descriptor_present": data_descriptor_present,
            "local_extra_field_ids": sorted(local_extra_ids),
            "local_extra_field_lengths": local_extra_lengths,
            "local_extra_field_sequence": local_seq,
            "central_extra_field_ids": sorted(central_extra_ids),
            "central_extra_field_lengths": central_extra_lengths,
            "central_extra_field_sequence": central_seq,
        }

    def _extract_subsidiary_features(
        self,
        cdhs: List[CentralDirectoryHeaderRecord],
        lfhs: List[Any],
    ) -> Dict[str, Any]:
        """Extract Subsidiary Features (Algorithm 3: Contextual low-weight features)."""
        all_names = [c.file_name for c in cdhs]

        # 1. __MACOSX folder existence
        has_macosx = any(name.startswith("__MACOSX/") or "/__MACOSX/" in name for name in all_names)

        # 2. Unicode normalization form (NFD vs NFC)
        unicode_norm = detect_unicode_normalization(all_names)

        # 3. Filename encoding
        # Check Bit 11 (EFS) or Unicode Path 0x7075
        has_efs = any(bool(c.gp_bit_flag & 0x0800) for c in cdhs)
        has_7075 = any(any(b.header_id == EXTRA_HEADER_UNICODE_PATH for b in c.extra_fields) for c in cdhs)
        if has_efs or has_7075:
            encoding = "UTF-8"
        else:
            encoding = "DEFAULT"

        # 4. Nanosecond pattern from NTFS 0x000A
        nano_pattern = self._determine_nanosecond_pattern(cdhs, lfhs)

        # 5. UID / GID extraction from 0x7875 or 0x5855
        uid, gid = self._extract_uid_gid(cdhs, lfhs)

        # 6. Double Zipping behavior on nested .zip files
        double_zipping = self._detect_double_zipping(cdhs)

        # 7. Root folder and empty folder headers
        root_folder_exists, empty_folder_exists = self._analyze_folder_headers(cdhs)

        # 8. Timezone offset estimation
        timezone_offset = self._calculate_timezone_offset(cdhs)

        # 9. Alphabetical ordering
        is_alphabetical = self._check_alphabetical_order(all_names)

        return {
            "nanosecond_pattern": nano_pattern,
            "has_macosx_folder": has_macosx,
            "unicode_normalization": unicode_norm,
            "filename_encoding": encoding,
            "root_folder_header_exists": root_folder_exists,
            "empty_folder_headers_exist": empty_folder_exists,
            "uid": uid,
            "gid": gid,
            "double_zipping": double_zipping,
            "timezone_offset_minutes": timezone_offset,
            "is_alphabetical_order": is_alphabetical,
        }

    def _determine_nanosecond_pattern(
        self,
        cdhs: List[CentralDirectoryHeaderRecord],
        lfhs: List[Any],
    ) -> str:
        """Examine 0x000A NTFS extra fields to detect WinZip truncation (fff0000)."""
        patterns_found: Set[str] = set()

        # Check CDH blocks first
        for cdh in cdhs:
            for b in cdh.extra_fields:
                if b.header_id == EXTRA_HEADER_NTFS:
                    decoded = ExtraFieldParser.decode_ntfs(b.raw_data)
                    if decoded and decoded.nano_pattern:
                        patterns_found.add(decoded.nano_pattern)

        # Check LFH blocks if needed
        for lfh in lfhs:
            for b in lfh.extra_fields:
                if b.header_id == EXTRA_HEADER_NTFS:
                    decoded = ExtraFieldParser.decode_ntfs(b.raw_data)
                    if decoded and decoded.nano_pattern:
                        patterns_found.add(decoded.nano_pattern)

        if NANO_PATTERN_WINZIP in patterns_found:
            return NANO_PATTERN_WINZIP
        if NANO_PATTERN_FULL in patterns_found:
            return NANO_PATTERN_FULL
        if NANO_PATTERN_ZERO in patterns_found:
            return NANO_PATTERN_ZERO
        return "N/A"

    def _extract_uid_gid(
        self,
        cdhs: List[CentralDirectoryHeaderRecord],
        lfhs: List[Any],
    ) -> Tuple[Optional[int], Optional[int]]:
        """Extract UID and GID from 0x7875 or 0x5855 extra fields."""
        # Try 0x7875 in CDH or LFH
        for cdh in cdhs:
            for b in cdh.extra_fields:
                if b.header_id == EXTRA_HEADER_UNIX_UID_GID:
                    decoded = ExtraFieldParser.decode_unix_uid_gid(b.raw_data)
                    if decoded:
                        return decoded.uid, decoded.gid

        for lfh in lfhs:
            for b in lfh.extra_fields:
                if b.header_id == EXTRA_HEADER_UNIX_UID_GID:
                    decoded = ExtraFieldParser.decode_unix_uid_gid(b.raw_data)
                    if decoded:
                        return decoded.uid, decoded.gid

        # Try 0x5855 (Bandizip on macOS often stores UID/GID in LFH)
        for lfh in lfhs:
            for b in lfh.extra_fields:
                if b.header_id == EXTRA_HEADER_UNIX_5855:
                    decoded_5855 = ExtraFieldParser.decode_unix_5855(b.raw_data)
                    if decoded_5855 and decoded_5855.uid is not None:
                        return decoded_5855.uid, decoded_5855.gid

        return None, None

    def _detect_double_zipping(
        self, cdhs: List[CentralDirectoryHeaderRecord]
    ) -> Optional[str]:
        """Detect whether nested .zip files are recompressed (Deflate) or stored as binary (Store)."""
        nested_zips = [c for c in cdhs if c.file_name.lower().endswith(".zip")]
        if not nested_zips:
            return None

        for nz in nested_zips:
            # Compression method 0 = Store (WinRAR / Windows Built-in)
            if nz.compression_method == 0:
                return "STORED"
            # Compression method 8 = Deflated (WinZip / 7-zip / Bandizip)
            if nz.compression_method == 8:
                return "RECOMPRESSED"

        return "STORED"

    def _analyze_folder_headers(
        self, cdhs: List[CentralDirectoryHeaderRecord]
    ) -> Tuple[Optional[bool], bool]:
        """Check if root folder header exists (Bảng 6) and if empty folder headers exist."""
        all_names = [c.file_name for c in cdhs]
        folder_names = [name for name in all_names if name.endswith("/")]

        # Determine if there are nested directories
        root_candidates: Set[str] = set()
        for name in all_names:
            parts = name.split("/")
            if len(parts) > 1 and parts[0]:
                root_candidates.add(parts[0] + "/")

        if not root_candidates:
            root_folder_header_exists = None
        else:
            # Check if all candidate root directories have an explicit entry in CDH
            root_folder_header_exists = all(root in folder_names for root in root_candidates)

        # Check for empty folders
        # An empty folder entry has no files prefixed with that folder path
        empty_folder_exists = False
        for fld in folder_names:
            sub_items = [name for name in all_names if name != fld and name.startswith(fld)]
            if not sub_items:
                empty_folder_exists = True
                break

        return root_folder_header_exists, empty_folder_exists

    def _calculate_timezone_offset(
        self, cdhs: List[CentralDirectoryHeaderRecord]
    ) -> Optional[int]:
        """Calculate timezone difference (in minutes) between DOS local time and UTC extra fields."""
        for cdh in cdhs:
            dos_dt = dos_to_datetime(cdh.last_mod_time, cdh.last_mod_date)
            if not dos_dt:
                continue

            utc_dt: Optional[datetime] = None

            # Check 0x000A NTFS
            for b in cdh.extra_fields:
                if b.header_id == EXTRA_HEADER_NTFS:
                    ntfs = ExtraFieldParser.decode_ntfs(b.raw_data)
                    if ntfs and ntfs.mtime:
                        utc_dt = ntfs.mtime
                        break

            # Check 0x5455 Extended Timestamp
            if not utc_dt:
                for b in cdh.extra_fields:
                    if b.header_id == EXTRA_HEADER_EXTENDED_TS:
                        ext_ts = ExtraFieldParser.decode_extended_timestamp(b.raw_data)
                        if ext_ts and ext_ts.mtime:
                            utc_dt = ext_ts.mtime
                            break

            # Check 0x5855 Unix
            if not utc_dt:
                for b in cdh.extra_fields:
                    if b.header_id == EXTRA_HEADER_UNIX_5855:
                        u5855 = ExtraFieldParser.decode_unix_5855(b.raw_data)
                        if u5855 and u5855.mtime:
                            utc_dt = u5855.mtime
                            break

            if utc_dt:
                naive_utc = utc_dt.replace(tzinfo=None)
                delta_sec = (dos_dt - naive_utc).total_seconds()
                # Round to nearest 15-minute boundary
                offset_minutes = int(round(delta_sec / 60.0 / 15.0) * 15)
                return offset_minutes

        return None

    def _check_alphabetical_order(self, names: List[str]) -> bool:
        """Check if archive entries follow alphabetical order (Paper Section 3.2.3)."""
        # Filter out __MACOSX resource fork entries for fair ordering assessment
        clean_names = [n for n in names if not n.startswith("__MACOSX/")]
        if len(clean_names) <= 1:
            return True

        return clean_names == sorted(clean_names)
