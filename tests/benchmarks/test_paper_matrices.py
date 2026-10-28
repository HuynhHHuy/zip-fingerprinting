"""Benchmark tests validating implementation against Table 6 and Table 7 in Um et al. (2021)."""

import pytest

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
)
from zip_fingerprint.rules import (
    RULES_TABLE_WINDOWS,
    RULES_TABLE_MACOS,
    RULES_TABLE_UBUNTU,
    ALL_RULES,
    get_rule,
    get_rules_for_os,
    get_all_rules,
)


def test_windows_table_6_rules() -> None:
    """Validate Table 6 (Windows 10 v2004) ground truth rules."""
    assert len(RULES_TABLE_WINDOWS) == 5
    assert set(RULES_TABLE_WINDOWS.keys()) == {
        "WinRAR",
        "WinZip",
        "7-Zip",
        "Bandizip",
        "Compressed folder",
    }

    # All Windows entries must report Host OS = 0
    for rule in RULES_TABLE_WINDOWS.values():
        assert rule.host_os_code == HostOS.MSDOS_WINDOWS
        assert rule.target_os == "Windows"
        assert rule.unicode_normalization == "NFC"
        assert rule.is_alphabetical_order is True

    # 1. WinRAR
    winrar = RULES_TABLE_WINDOWS["WinRAR"]
    assert winrar.central_extra_ids == (EXTRA_HEADER_NTFS,)
    assert winrar.central_extra_sequence == (EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH)
    assert winrar.nanosecond_pattern == NANO_PATTERN_FULL
    assert winrar.double_zipping_behavior is False  # Does not re-compress
    assert winrar.root_folder_header_exists is True

    # 2. WinZip
    winzip = RULES_TABLE_WINDOWS["WinZip"]
    assert winzip.central_extra_ids == (EXTRA_HEADER_NTFS,)
    assert winzip.central_extra_sequence == (EXTRA_HEADER_UNICODE_PATH, EXTRA_HEADER_NTFS)
    assert winzip.nanosecond_pattern == NANO_PATTERN_WINZIP  # Distinctive fff0000
    assert winzip.double_zipping_behavior is True
    assert winzip.root_folder_header_exists is True

    # 3. 7-Zip
    sevenzip = RULES_TABLE_WINDOWS["7-Zip"]
    assert sevenzip.central_extra_ids == (EXTRA_HEADER_NTFS,)
    assert sevenzip.local_extra_ids_unicode == ()  # Does not write 0x7075
    assert sevenzip.nanosecond_pattern == NANO_PATTERN_FULL
    assert sevenzip.double_zipping_behavior is True
    assert sevenzip.root_folder_header_exists is True

    # 4. Bandizip
    bandizip = RULES_TABLE_WINDOWS["Bandizip"]
    assert bandizip.central_extra_ids == (EXTRA_HEADER_NTFS,)
    assert bandizip.central_extra_sequence == (EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH)
    assert bandizip.nanosecond_pattern == NANO_PATTERN_FULL
    assert bandizip.double_zipping_behavior is True
    assert bandizip.root_folder_header_exists is True

    # 5. Compressed folder (Windows Built-in)
    comp_folder = RULES_TABLE_WINDOWS["Compressed folder"]
    assert comp_folder.local_extra_ids == ()
    assert comp_folder.central_extra_ids == ()
    assert comp_folder.nanosecond_pattern is None
    assert comp_folder.double_zipping_behavior is False
    assert comp_folder.root_folder_header_exists is False  # Key differentiator!


def test_macos_table_7_rules() -> None:
    """Validate Table 7 macOS ground truth rules."""
    assert len(RULES_TABLE_MACOS) == 4
    assert set(RULES_TABLE_MACOS.keys()) == {
        "WinZip",
        "Bandizip",
        "Compress",
        "zip",
    }

    for rule in RULES_TABLE_MACOS.values():
        assert rule.host_os_code == HostOS.UNIX_LINUX
        assert rule.target_os == "macOS"
        assert rule.unicode_normalization == "NFD"
        assert rule.default_uid_gid == (MACOS_DEFAULT_UID, MACOS_DEFAULT_GID)

    # 1. macOS WinZip
    m_winzip = RULES_TABLE_MACOS["WinZip"]
    assert m_winzip.local_extra_ids == ()
    assert m_winzip.central_extra_ids == ()
    assert m_winzip.double_zipping_behavior is True
    assert m_winzip.has_macosx_folder is False

    # 2. macOS Bandizip
    m_bandizip = RULES_TABLE_MACOS["Bandizip"]
    assert m_bandizip.local_extra_ids == (EXTRA_HEADER_UNIX_5855,)
    assert m_bandizip.central_extra_ids == (EXTRA_HEADER_UNIX_5855,)
    assert m_bandizip.double_zipping_behavior is True
    assert m_bandizip.has_macosx_folder is False

    # 3. macOS Compress
    m_compress = RULES_TABLE_MACOS["Compress"]
    assert m_compress.local_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert m_compress.central_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert m_compress.extra_5455_length_local == 13
    assert m_compress.extra_5455_length_central == 13
    assert m_compress.data_descriptor_required is True
    assert m_compress.has_macosx_folder is True
    assert m_compress.double_zipping_behavior is True

    # 4. macOS zip CLI
    m_zip = RULES_TABLE_MACOS["zip"]
    assert m_zip.local_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert m_zip.central_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert m_zip.extra_5455_length_local == 9
    assert m_zip.extra_5455_length_central == 5
    assert m_zip.data_descriptor_required is False
    assert m_zip.has_macosx_folder is False
    assert m_zip.double_zipping_behavior is False


def test_ubuntu_table_7_rules() -> None:
    """Validate Table 7 Ubuntu ground truth rules."""
    assert len(RULES_TABLE_UBUNTU) == 3
    assert set(RULES_TABLE_UBUNTU.keys()) == {
        "7-Zip",
        "Compress",
        "zip",
    }

    for rule in RULES_TABLE_UBUNTU.values():
        assert rule.host_os_code == HostOS.UNIX_LINUX
        assert rule.target_os == "Ubuntu"
        assert rule.unicode_normalization == "NFC"
        assert rule.default_uid_gid == (UBUNTU_DEFAULT_UID, UBUNTU_DEFAULT_GID)

    # 1. Ubuntu 7-Zip (7zz)
    u_sevenzip = RULES_TABLE_UBUNTU["7-Zip"]
    assert u_sevenzip.local_extra_ids == ()
    assert u_sevenzip.central_extra_ids == (EXTRA_HEADER_NTFS,)
    assert u_sevenzip.nanosecond_pattern == NANO_PATTERN_FULL
    assert u_sevenzip.double_zipping_behavior is True

    # 2. Ubuntu Compress
    u_compress = RULES_TABLE_UBUNTU["Compress"]
    assert u_compress.local_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert u_compress.central_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert u_compress.extra_5455_length_local == 13
    assert u_compress.extra_5455_length_central == 13
    assert u_compress.data_descriptor_required is True
    assert u_compress.has_macosx_folder is False
    assert u_compress.double_zipping_behavior is True

    # 3. Ubuntu zip CLI
    u_zip = RULES_TABLE_UBUNTU["zip"]
    assert u_zip.local_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert u_zip.central_extra_ids == (EXTRA_HEADER_EXTENDED_TS, EXTRA_HEADER_UNIX_UID_GID)
    assert u_zip.extra_5455_length_local == 9
    assert u_zip.extra_5455_length_central == 5
    assert u_zip.data_descriptor_required is False
    assert u_zip.has_macosx_folder is False
    assert u_zip.double_zipping_behavior is False


def test_rule_helpers() -> None:
    """Test lookup helper functions."""
    assert len(get_all_rules()) == 12
    assert len(ALL_RULES) == 12

    # Lookup by OS
    assert len(get_rules_for_os("windows")) == 5
    assert len(get_rules_for_os("macos")) == 4
    assert len(get_rules_for_os("ubuntu")) == 3
    assert len(get_rules_for_os("unknown")) == 0

    # Lookup specific rule
    rule_win = get_rule("Windows", "WinZip")
    assert rule_win is not None
    assert rule_win.nanosecond_pattern == NANO_PATTERN_WINZIP

    rule_mac = get_rule("macOS", "Bandizip")
    assert rule_mac is not None
    assert rule_mac.local_extra_ids == (EXTRA_HEADER_UNIX_5855,)

    rule_ubu = get_rule("Ubuntu", "7-Zip")
    assert rule_ubu is not None
    assert rule_ubu.central_extra_ids == (EXTRA_HEADER_NTFS,)

    # Non-existent rule or OS
    assert get_rule("Windows", "NonExistentApp") is None
    assert get_rule("FreeBSD", "App") is None
