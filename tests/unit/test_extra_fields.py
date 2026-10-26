"""Unit tests for ExtraFieldParser."""

import struct
from datetime import datetime, timezone
import pytest

from zip_fingerprint.constants import (
    NANO_PATTERN_WINZIP,
    NANO_PATTERN_FULL,
    NANO_PATTERN_ZERO,
)
from zip_fingerprint.extra_fields import (
    ExtraFieldParser,
    DecodedNTFS,
    DecodedExtendedTimestamp,
    DecodedUnixUIDGID,
    DecodedUnix5855,
    DecodedUnicodePath,
    filetime_to_datetime,
    get_filetime_nano_pattern,
)
from zip_fingerprint.models import ExtraFieldBlock


def test_split_blocks() -> None:
    """Test splitting raw bytes into multiple ExtraFieldBlock entries."""
    block1 = struct.pack("<HH4s", 0x000A, 4, b"AAAA")
    block2 = struct.pack("<HH6s", 0x5455, 6, b"BBBBBB")
    raw = block1 + block2

    blocks = ExtraFieldParser.parse_blocks(raw)
    assert len(blocks) == 2
    assert blocks[0].header_id == 0x000A
    assert blocks[0].data_size == 4
    assert blocks[0].raw_data == b"AAAA"

    assert blocks[1].header_id == 0x5455
    assert blocks[1].data_size == 6
    assert blocks[1].raw_data == b"BBBBBB"


def test_decode_ntfs_normal() -> None:
    """Test decoding 0x000A NTFS field with realistic Windows FILETIME."""
    # 2021-01-01 00:00:00 UTC corresponds to FILETIME: 132539328000000000 (zero fractional part)
    ft_zero = 132539328000000000
    raw_zero = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft_zero, ft_zero, ft_zero)
    decoded_zero = ExtraFieldParser.decode_ntfs(raw_zero)
    assert decoded_zero is not None
    assert decoded_zero.mtime_filetime == ft_zero
    assert decoded_zero.mtime == datetime(2021, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert decoded_zero.nano_pattern == NANO_PATTERN_ZERO

    # WinZip pattern: rounded to milliseconds (last 4 decimal digits are 0000: .1470000)
    # 1 tick = 100ns, 10,000 ticks = 1ms. 147ms = 1,470,000 ticks.
    ft_winzip = 132539328000000000 + 1_470_000
    raw_winzip = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft_winzip, ft_winzip, ft_winzip)
    decoded_winzip = ExtraFieldParser.decode_ntfs(raw_winzip)
    assert decoded_winzip is not None
    assert decoded_winzip.is_winzip_nano_pattern is True
    assert decoded_winzip.nano_pattern == NANO_PATTERN_WINZIP

    # High precision non-zero nanoseconds (WinRAR / 7-zip / Bandizip)
    ft_precise = 132539328001234567
    raw_precise = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft_precise, ft_precise, ft_precise)
    decoded_precise = ExtraFieldParser.decode_ntfs(raw_precise)
    assert decoded_precise is not None
    assert decoded_precise.is_winzip_nano_pattern is False
    assert decoded_precise.nano_pattern == NANO_PATTERN_FULL


def test_get_filetime_nano_pattern() -> None:
    """Test nanosecond pattern classification helper."""
    assert get_filetime_nano_pattern(0) == NANO_PATTERN_ZERO
    assert get_filetime_nano_pattern(132539328000000000) == NANO_PATTERN_ZERO
    assert get_filetime_nano_pattern(132539328001470000) == NANO_PATTERN_WINZIP
    assert get_filetime_nano_pattern(132539328001234567) == NANO_PATTERN_FULL


def test_decode_extended_timestamp_lengths() -> None:
    """Test decoding 0x5455 with 13, 9, and 5 bytes payloads."""
    ts1 = 1600000000
    ts2 = 1600000100
    ts3 = 1600000200

    # 13 bytes (flags [1] + 3 timestamps [12]) -> Compress GUI
    raw_13 = struct.pack("<BIII", 0x07, ts1, ts2, ts3)
    dec_13 = ExtraFieldParser.decode_extended_timestamp(raw_13)
    assert dec_13 is not None
    assert dec_13.data_length == 13
    assert dec_13.mtime == datetime.fromtimestamp(ts1, tz=timezone.utc)
    assert dec_13.atime == datetime.fromtimestamp(ts2, tz=timezone.utc)
    assert dec_13.ctime == datetime.fromtimestamp(ts3, tz=timezone.utc)

    # 9 bytes (flags [1] + 2 timestamps [8]) -> zip terminal LFH
    raw_9 = struct.pack("<BII", 0x03, ts1, ts2)
    dec_9 = ExtraFieldParser.decode_extended_timestamp(raw_9)
    assert dec_9 is not None
    assert dec_9.data_length == 9
    assert dec_9.mtime is not None
    assert dec_9.atime is not None
    assert dec_9.ctime is None

    # 5 bytes (flags [1] + 1 timestamp [4]) -> zip terminal CDH
    raw_5 = struct.pack("<BI", 0x01, ts1)
    dec_5 = ExtraFieldParser.decode_extended_timestamp(raw_5)
    assert dec_5 is not None
    assert dec_5.data_length == 5
    assert dec_5.mtime is not None
    assert dec_5.atime is None


def test_decode_unix_uid_gid() -> None:
    """Test decoding 0x7875 UID/GID."""
    # Version 1, UID size 2 (501 macOS), GID size 2 (20 macOS)
    raw = struct.pack("<BBHBH", 1, 2, 501, 2, 20)
    decoded = ExtraFieldParser.decode_unix_uid_gid(raw)
    assert decoded is not None
    assert decoded.version == 1
    assert decoded.uid == 501
    assert decoded.gid == 20


def test_decode_unix_5855() -> None:
    """Test decoding 0x5855 Bandizip macOS extra field."""
    ts_atime = 1610000000
    ts_mtime = 1610000500
    raw = struct.pack("<IIHH", ts_atime, ts_mtime, 501, 20)
    decoded = ExtraFieldParser.decode_unix_5855(raw)
    assert decoded is not None
    assert decoded.atime == datetime.fromtimestamp(ts_atime, tz=timezone.utc)
    assert decoded.mtime == datetime.fromtimestamp(ts_mtime, tz=timezone.utc)
    assert decoded.uid == 501
    assert decoded.gid == 20


def test_decode_unicode_path() -> None:
    """Test decoding 0x7075 Unicode path."""
    name = "Tài liệu mật.pdf".encode("utf-8")
    crc = 0x12345678
    raw = struct.pack("<BI", 1, crc) + name
    decoded = ExtraFieldParser.decode_unicode_path(raw)
    assert decoded is not None
    assert decoded.version == 1
    assert decoded.name_crc32 == crc
    assert decoded.unicode_path == "Tài liệu mật.pdf"
