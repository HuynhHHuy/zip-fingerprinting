"""Forensic classification rules based on empirical matrices in Um et al. (2021).

Encodes Table 6 (Windows), Table 7 (macOS and Ubuntu), and Flowchart/Algorithms 1-3.

Reference:
    Minji Um, Jaehyeok Han, Sangjin Lee.
    "File fingerprinting of the ZIP format for identifying and tracking provenance",
    Forensic Science International: Digital Investigation 39 (2021) 301271.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from zip_fingerprint.constants import (
    EXTRA_HEADER_NTFS,
    EXTRA_HEADER_EXTENDED_TS,
    EXTRA_HEADER_UNIX_UID_GID,
    EXTRA_HEADER_UNIX_5855,
    EXTRA_HEADER_UNICODE_PATH,
    HostOS,
    MACOS_DEFAULT_UID,
    MACOS_DEFAULT_GID,
    UBUNTU_DEFAULT_UID,
    UBUNTU_DEFAULT_GID,
    NANO_PATTERN_WINZIP,
    NANO_PATTERN_FULL,
    NANO_PATTERN_ZERO,
)


@dataclass(frozen=True)
class FingerprintRule:
    """Represents an empirical forensic fingerprint profile for a specific OS and application."""
    target_os: str                        # "Windows", "macOS", "Ubuntu"
    application: str                      # "WinRAR", "WinZip", "7-Zip", "Bandizip", "Compressed folder", "Compress", "zip"
    host_os_code: int                     # Host OS byte from CDH (0: Windows, 3: Unix/macOS/Ubuntu)

    # High-Weight Criteria (Algorithm 1 & 2)
    data_descriptor_required: bool        # True for macOS Compress and Ubuntu Compress
    local_extra_ids: Tuple[int, ...]      # Base extra fields in LFH (ASCII filename)
    central_extra_ids: Tuple[int, ...]    # Base extra fields in CDH (ASCII filename)
    local_extra_ids_unicode: Tuple[int, ...] = ()    # LFH extra fields when non-ASCII (e.g. KR/VN)
    central_extra_ids_unicode: Tuple[int, ...] = ()  # CDH extra fields when non-ASCII
    central_extra_sequence: Tuple[int, ...] = ()     # Expected order of extra headers in CDH
    extra_5455_length_local: Optional[int] = None    # 13 for Compress, 9 for zip
    extra_5455_length_central: Optional[int] = None  # 13 for Compress, 5 for zip

    # Subsidiary Criteria (Algorithm 3)
    nanosecond_pattern: Optional[str] = None         # "fff0000" for WinZip, "fffffff" for WinRAR/7z/Bandizip
    has_macosx_folder: Optional[bool] = None         # True for macOS Compress
    unicode_normalization: Optional[str] = None      # "NFD" for macOS, "NFC" for Windows/Ubuntu
    double_zipping_behavior: Optional[bool] = None   # True: re-compressed, False: store uncompressed
    root_folder_header_exists: Optional[bool] = None # False for Compressed folder, True for others
    default_uid_gid: Optional[Tuple[int, int]] = None# (501, 20) for macOS, (1000, 1000) for Ubuntu
    is_alphabetical_order: bool = True
    notes: str = ""


# ==============================================================================
# TABLE 6: Windows Ground Truth Rules (Windows 10 v2004 EN & KR)
# ==============================================================================

RULES_WINDOWS_WINRAR = FingerprintRule(
    target_os="Windows",
    application="WinRAR",
    host_os_code=HostOS.MSDOS_WINDOWS,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(EXTRA_HEADER_NTFS,),
    local_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH,),
    central_extra_ids_unicode=(EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH),
    central_extra_sequence=(EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH),
    nanosecond_pattern=NANO_PATTERN_FULL,
    unicode_normalization="NFC",
    double_zipping_behavior=False,  # WinRAR recognizes .zip extension and does not re-compress
    root_folder_header_exists=True,
    is_alphabetical_order=True,
    notes="WinRAR records 0x000A before 0x7075; full nanosecond precision; does not re-compress inner .zip",
)

RULES_WINDOWS_WINZIP = FingerprintRule(
    target_os="Windows",
    application="WinZip",
    host_os_code=HostOS.MSDOS_WINDOWS,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(EXTRA_HEADER_NTFS,),
    local_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH,),
    central_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH, EXTRA_HEADER_NTFS),
    central_extra_sequence=(EXTRA_HEADER_UNICODE_PATH, EXTRA_HEADER_NTFS),
    nanosecond_pattern=NANO_PATTERN_WINZIP,  # Distinctive fff0000 millisecond rounding
    unicode_normalization="NFC",
    double_zipping_behavior=True,   # WinZip re-compresses inner .zip files
    root_folder_header_exists=True,
    is_alphabetical_order=True,
    notes="WinZip records 0x7075 before 0x000A in CDH; rounds nanosecond to millisecond (fff0000); re-compresses .zip",
)

RULES_WINDOWS_7ZIP = FingerprintRule(
    target_os="Windows",
    application="7-Zip",
    host_os_code=HostOS.MSDOS_WINDOWS,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(EXTRA_HEADER_NTFS,),
    local_extra_ids_unicode=(),     # 7-Zip does NOT generate 0x7075 even for non-ASCII
    central_extra_ids_unicode=(EXTRA_HEADER_NTFS,),
    central_extra_sequence=(EXTRA_HEADER_NTFS,),
    nanosecond_pattern=NANO_PATTERN_FULL,
    unicode_normalization="NFC",
    double_zipping_behavior=True,   # 7-Zip re-compresses inner .zip files
    root_folder_header_exists=True,
    is_alphabetical_order=True,
    notes="7-Zip Windows only generates 0x000A (no 0x7075); full nanoseconds; re-compresses inner .zip",
)

RULES_WINDOWS_BANDIZIP = FingerprintRule(
    target_os="Windows",
    application="Bandizip",
    host_os_code=HostOS.MSDOS_WINDOWS,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(EXTRA_HEADER_NTFS,),
    local_extra_ids_unicode=(EXTRA_HEADER_UNICODE_PATH,),
    central_extra_ids_unicode=(EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH),
    central_extra_sequence=(EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH),
    nanosecond_pattern=NANO_PATTERN_FULL,
    unicode_normalization="NFC",
    double_zipping_behavior=True,   # Bandizip re-compresses inner .zip files
    root_folder_header_exists=True,
    is_alphabetical_order=True,
    notes="Bandizip Windows records 0x000A before 0x7075; full nanoseconds; re-compresses inner .zip",
)

RULES_WINDOWS_COMPRESSED_FOLDER = FingerprintRule(
    target_os="Windows",
    application="Compressed folder",
    host_os_code=HostOS.MSDOS_WINDOWS,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(),           # Windows Built-in does NOT record any extra fields
    local_extra_ids_unicode=(),
    central_extra_ids_unicode=(),
    central_extra_sequence=(),
    nanosecond_pattern=None,
    unicode_normalization="NFC",
    double_zipping_behavior=False,  # Compressed folder does not re-compress inner .zip
    root_folder_header_exists=False,# Crucial distinction: DOES NOT create header for root directory!
    is_alphabetical_order=True,
    notes="Windows Compressed Folder omits all extra fields; crucially omits root folder header; does not re-compress",
)

RULES_TABLE_WINDOWS: Dict[str, FingerprintRule] = {
    "WinRAR": RULES_WINDOWS_WINRAR,
    "WinZip": RULES_WINDOWS_WINZIP,
    "7-Zip": RULES_WINDOWS_7ZIP,
    "Bandizip": RULES_WINDOWS_BANDIZIP,
    "Compressed folder": RULES_WINDOWS_COMPRESSED_FOLDER,
}


# ==============================================================================
# TABLE 7: macOS Ground Truth Rules (macOS 10.15 Catalina)
# ==============================================================================

RULES_MACOS_WINZIP = FingerprintRule(
    target_os="macOS",
    application="WinZip",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(),
    unicode_normalization="NFD",
    double_zipping_behavior=True,
    has_macosx_folder=False,
    default_uid_gid=(MACOS_DEFAULT_UID, MACOS_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="macOS WinZip has no extra fields; Host OS is 0x03 Unix; re-compresses inner .zip",
)

RULES_MACOS_BANDIZIP = FingerprintRule(
    target_os="macOS",
    application="Bandizip",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=False,
    local_extra_ids=(EXTRA_HEADER_UNIX_5855,),
    central_extra_ids=(EXTRA_HEADER_UNIX_5855,),
    central_extra_sequence=(EXTRA_HEADER_UNIX_5855,),
    unicode_normalization="NFD",
    double_zipping_behavior=True,
    has_macosx_folder=False,
    default_uid_gid=(MACOS_DEFAULT_UID, MACOS_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="macOS Bandizip uniquely utilizes 0x5855 instead of 0x7875; Host OS is 0x03",
)

RULES_MACOS_COMPRESS = FingerprintRule(
    target_os="macOS",
    application="Compress",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=True,   # macOS Archive Utility defaults to creating Data Descriptors
    local_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_sequence=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    extra_5455_length_local=13,      # 13 bytes (flags + mod + acc + chg)
    extra_5455_length_central=13,    # 13 bytes
    unicode_normalization="NFD",     # Apple HFS+/APFS decomposes Unicode into NFD
    double_zipping_behavior=True,
    has_macosx_folder=True,          # Creates __MACOSX resource fork folder
    default_uid_gid=(MACOS_DEFAULT_UID, MACOS_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="macOS Archive Utility: 13-byte 0x5455, Data Descriptor present, creates __MACOSX/, NFD encoding",
)

RULES_MACOS_ZIP = FingerprintRule(
    target_os="macOS",
    application="zip",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=False,
    local_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_sequence=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    extra_5455_length_local=9,       # 9 bytes in LFH (flags + mod + acc)
    extra_5455_length_central=5,     # 5 bytes in CDH (flags + mod)
    unicode_normalization="NFD",
    double_zipping_behavior=False,   # zip CLI does not re-compress inner .zip
    has_macosx_folder=False,         # terminal zip command does not create __MACOSX/
    default_uid_gid=(MACOS_DEFAULT_UID, MACOS_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="macOS zip CLI: 9b local / 5b central 0x5455, no Data Descriptor, no __MACOSX, does not re-compress",
)

RULES_TABLE_MACOS: Dict[str, FingerprintRule] = {
    "WinZip": RULES_MACOS_WINZIP,
    "Bandizip": RULES_MACOS_BANDIZIP,
    "Compress": RULES_MACOS_COMPRESS,
    "zip": RULES_MACOS_ZIP,
}


# ==============================================================================
# TABLE 7: Ubuntu Ground Truth Rules (Ubuntu 20.04 LTS)
# ==============================================================================

RULES_UBUNTU_7ZIP = FingerprintRule(
    target_os="Ubuntu",
    application="7-Zip",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=False,
    local_extra_ids=(),
    central_extra_ids=(EXTRA_HEADER_NTFS,),  # Ubuntu 7zz uniquely writes 0x000A in Central Directory
    central_extra_sequence=(EXTRA_HEADER_NTFS,),
    nanosecond_pattern=NANO_PATTERN_FULL,
    unicode_normalization="NFC",
    double_zipping_behavior=True,
    has_macosx_folder=False,
    default_uid_gid=(UBUNTU_DEFAULT_UID, UBUNTU_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="Ubuntu 7-Zip (7zz): writes 0x000A in CDH despite running on Linux; full nanoseconds",
)

RULES_UBUNTU_COMPRESS = FingerprintRule(
    target_os="Ubuntu",
    application="Compress",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=True,   # Ubuntu Archive Manager defaults to Data Descriptors
    local_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_sequence=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    extra_5455_length_local=13,      # 13 bytes
    extra_5455_length_central=13,    # 13 bytes
    unicode_normalization="NFC",     # Linux native UTF-8 is NFC
    double_zipping_behavior=True,
    has_macosx_folder=False,
    default_uid_gid=(UBUNTU_DEFAULT_UID, UBUNTU_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="Ubuntu Archive Manager: 13-byte 0x5455 in both headers, Data Descriptor present, NFC encoding",
)

RULES_UBUNTU_ZIP = FingerprintRule(
    target_os="Ubuntu",
    application="zip",
    host_os_code=HostOS.UNIX_LINUX,
    data_descriptor_required=False,
    local_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_ids=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    central_extra_sequence=(EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID),
    extra_5455_length_local=9,       # 9 bytes in LFH
    extra_5455_length_central=5,     # 5 bytes in CDH
    unicode_normalization="NFC",
    double_zipping_behavior=False,   # zip CLI does not re-compress inner .zip
    has_macosx_folder=False,
    default_uid_gid=(UBUNTU_DEFAULT_UID, UBUNTU_DEFAULT_GID),
    is_alphabetical_order=True,
    notes="Ubuntu zip CLI: 9b local / 5b central 0x5455, no Data Descriptor, NFC encoding, does not re-compress",
)

RULES_TABLE_UBUNTU: Dict[str, FingerprintRule] = {
    "7-Zip": RULES_UBUNTU_7ZIP,
    "Compress": RULES_UBUNTU_COMPRESS,
    "zip": RULES_UBUNTU_ZIP,
}


# ==============================================================================
# Aggregated Catalog & Query Helpers
# ==============================================================================

ALL_RULES: List[FingerprintRule] = [
    *RULES_TABLE_WINDOWS.values(),
    *RULES_TABLE_MACOS.values(),
    *RULES_TABLE_UBUNTU.values(),
]


def get_rule(target_os: str, application: str) -> Optional[FingerprintRule]:
    """Retrieve rule definition by OS and application name."""
    os_normalized = target_os.lower()
    if "win" in os_normalized:
        return RULES_TABLE_WINDOWS.get(application)
    elif "mac" in os_normalized:
        return RULES_TABLE_MACOS.get(application)
    elif "ubu" in os_normalized or "linux" in os_normalized:
        return RULES_TABLE_UBUNTU.get(application)
    return None


def get_rules_for_os(target_os: str) -> List[FingerprintRule]:
    """Return all rules applicable to a given OS ('Windows', 'macOS', 'Ubuntu')."""
    os_normalized = target_os.lower()
    if "win" in os_normalized:
        return list(RULES_TABLE_WINDOWS.values())
    elif "mac" in os_normalized:
        return list(RULES_TABLE_MACOS.values())
    elif "ubu" in os_normalized or "linux" in os_normalized:
        return list(RULES_TABLE_UBUNTU.values())
    return []


def get_all_rules() -> List[FingerprintRule]:
    """Return the complete list of all 12 empirical rules."""
    return list(ALL_RULES)
