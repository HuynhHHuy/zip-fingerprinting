"""Parser and decoder for ZIP Extra Field blocks based on Um et al. (2021)."""

import struct
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from zip_fingerprint.constants import (
    EXTRA_HEADER_NTFS,
    EXTRA_HEADER_EXTENDED_TS,
    EXTRA_HEADER_UNIX_UID_GID,
    EXTRA_HEADER_UNIX_5855,
    EXTRA_HEADER_UNICODE_PATH,
)
from zip_fingerprint.models import ExtraFieldBlock


# Windows FILETIME epoch is 1601-01-01 00:00:00 UTC
# 100-nanosecond intervals between 1601-01-01 and 1970-01-01 = 116444736000000000
WINDOWS_TICK = 10_000_000
EPOCH_AS_FILETIME = 116_444_736_000_000_000


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows 64-bit FILETIME (100-nanosecond intervals since Jan 1, 1601) to UTC datetime."""
    if filetime <= 0:
        return None
    try:
        unix_time = (filetime - EPOCH_AS_FILETIME) / WINDOWS_TICK
        return datetime.fromtimestamp(unix_time, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def get_filetime_nanoseconds_fraction(filetime: int) -> int:
    """Return the fraction of a second in nanoseconds (0 to 999,999,900) from 64-bit FILETIME."""
    # 1 tick = 100 ns -> modulo 10_000_000 gives 100-ns ticks within current second
    fraction_100ns = filetime % WINDOWS_TICK
    return fraction_100ns * 100


@dataclass
class DecodedNTFS:
    """Decoded 0x000A NTFS extra field (Table 1)."""
    mtime_filetime: int
    atime_filetime: int
    ctime_filetime: int
    mtime: Optional[datetime]
    atime: Optional[datetime]
    ctime: Optional[datetime]
    mtime_nano_hex: str  # Last 7 hex digits representing nanoseconds precision
    is_winzip_nano_pattern: bool  # True if ends with '0000' (fff0000)


@dataclass
class DecodedExtendedTimestamp:
    """Decoded 0x5455 Extended timestamp extra field (Table 2)."""
    flags: int
    data_length: int
    mtime: Optional[datetime] = None
    atime: Optional[datetime] = None
    ctime: Optional[datetime] = None


@dataclass
class DecodedUnixUIDGID:
    """Decoded 0x7875 Info-ZIP UNIX UID/GID extra field (Table 3)."""
    version: int
    uid: int
    gid: int


@dataclass
class DecodedUnix5855:
    """Decoded 0x5855 Info-ZIP Unix extra field (Table 4, Bandizip macOS)."""
    atime: Optional[datetime]
    mtime: Optional[datetime]
    uid: Optional[int] = None
    gid: Optional[int] = None


@dataclass
class DecodedUnicodePath:
    """Decoded 0x7075 Info-ZIP Unicode path extra field (Table 5)."""
    version: int
    name_crc32: int
    unicode_path: str


class ExtraFieldParser:
    """Decodes Extra Field payloads (0x000A, 0x5455, 0x7875, 0x5855, 0x7075)."""

    @staticmethod
    def parse_blocks(raw_bytes: bytes) -> List[ExtraFieldBlock]:
        """Split raw extra field byte buffer into individual blocks."""
        blocks: List[ExtraFieldBlock] = []
        idx = 0
        total_len = len(raw_bytes)

        while idx + 4 <= total_len:
            header_id, data_size = struct.unpack_from("<HH", raw_bytes, idx)
            idx += 4
            payload = raw_bytes[idx : idx + data_size]
            if len(payload) < data_size:
                blocks.append(
                    ExtraFieldBlock(
                        header_id=header_id, data_size=len(payload), raw_data=payload
                    )
                )
                break
            blocks.append(
                ExtraFieldBlock(
                    header_id=header_id, data_size=data_size, raw_data=payload
                )
            )
            idx += data_size

        return blocks

    @staticmethod
    def decode_ntfs(raw_data: bytes) -> Optional[DecodedNTFS]:
        """Decode 0x000A NTFS extra field (Paper Table 1, 32 bytes data size).
        
        Structure:
        - 4 bytes: Reserved
        - 2 bytes: Tag1 (0x0001)
        - 2 bytes: Size1 (0x0018 = 24 bytes)
        - 8 bytes: Mtime (Windows FILETIME)
        - 8 bytes: Atime (Windows FILETIME)
        - 8 bytes: Ctime (Windows FILETIME)
        """
        if len(raw_data) < 32:
            return None

        reserved, tag1, size1 = struct.unpack_from("<IHH", raw_data, 0)
        if tag1 != 0x0001 or size1 < 24:
            return None

        mtime_ft, atime_ft, ctime_ft = struct.unpack_from("<QQQ", raw_data, 8)

        # In Paper Table 6 & Section 3.1.1:
        # WinZip zero-pads the last 4 hex characters of nanoseconds fraction ('fff0000')
        # We check if low 16 bits of FILETIME are 0, or formatted nano hex ends in '0000'
        # In FILETIME, each tick is 100ns. 10,000 ticks = 1 millisecond.
        # WinZip often truncates precision to milliseconds, making the lowest digits 0.
        mtime_hex = f"{mtime_ft:016x}"
        # Extract fractional nanoseconds pattern
        nano_val = get_filetime_nanoseconds_fraction(mtime_ft)
        nano_str = f"{nano_val:09d}"

        # WinZip signature: lower part has four trailing zeros in hex representation of nanoseconds
        is_winzip = mtime_hex.endswith("0000") or (mtime_ft % 10000 == 0 and mtime_ft != 0)

        return DecodedNTFS(
            mtime_filetime=mtime_ft,
            atime_filetime=atime_ft,
            ctime_filetime=ctime_ft,
            mtime=filetime_to_datetime(mtime_ft),
            atime=filetime_to_datetime(atime_ft),
            ctime=filetime_to_datetime(ctime_ft),
            mtime_nano_hex=mtime_hex[-7:],
            is_winzip_nano_pattern=is_winzip,
        )

    @staticmethod
    def decode_extended_timestamp(raw_data: bytes) -> Optional[DecodedExtendedTimestamp]:
        """Decode 0x5455 Extended timestamp extra field (Paper Table 2).
        
        Length can be:
        - 13 bytes (flags [1] + mtime [4] + atime [4] + ctime [4]) -> Compress utility
        - 9 bytes (flags [1] + mtime [4] + atime [4]) -> zip command in LFH
        - 5 bytes (flags [1] + mtime [4]) -> zip command in CDH
        """
        length = len(raw_data)
        if length < 1:
            return None

        flags = raw_data[0]
        offset = 1
        mtime, atime, ctime = None, None, None

        if (flags & 0x01) and offset + 4 <= length:
            ts = struct.unpack_from("<I", raw_data, offset)[0]
            mtime = datetime.fromtimestamp(ts, tz=timezone.utc)
            offset += 4

        if (flags & 0x02) and offset + 4 <= length:
            ts = struct.unpack_from("<I", raw_data, offset)[0]
            atime = datetime.fromtimestamp(ts, tz=timezone.utc)
            offset += 4

        if (flags & 0x04) and offset + 4 <= length:
            ts = struct.unpack_from("<I", raw_data, offset)[0]
            ctime = datetime.fromtimestamp(ts, tz=timezone.utc)
            offset += 4

        return DecodedExtendedTimestamp(
            flags=flags,
            data_length=length,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
        )

    @staticmethod
    def decode_unix_uid_gid(raw_data: bytes) -> Optional[DecodedUnixUIDGID]:
        """Decode 0x7875 Info-ZIP UNIX UID/GID extra field (Paper Table 3).
        
        Format:
        - 1 byte: Version (currently 1)
        - 1 byte: UID Size (e.g., 4)
        - UID Size bytes: UID (variable)
        - 1 byte: GID Size (e.g., 4)
        - GID Size bytes: GID (variable)
        """
        if len(raw_data) < 3:
            return None

        version = raw_data[0]
        uid_size = raw_data[1]
        offset = 2

        if offset + uid_size > len(raw_data):
            return None
        uid = int.from_bytes(raw_data[offset : offset + uid_size], byteorder="little")
        offset += uid_size

        if offset >= len(raw_data):
            return None
        gid_size = raw_data[offset]
        offset += 1

        if offset + gid_size > len(raw_data):
            return None
        gid = int.from_bytes(raw_data[offset : offset + gid_size], byteorder="little")

        return DecodedUnixUIDGID(version=version, uid=uid, gid=gid)

    @staticmethod
    def decode_unix_5855(raw_data: bytes) -> Optional[DecodedUnix5855]:
        """Decode 0x5855 Info-ZIP Unix extra field (Paper Table 4, Bandizip macOS).
        
        Format:
        - 4 bytes: Atime (32-bit Unix)
        - 4 bytes: Mtime (32-bit Unix)
        - Optional 2 bytes: UID
        - Optional 2 bytes: GID
        """
        if len(raw_data) < 8:
            return None

        atime_raw, mtime_raw = struct.unpack_from("<II", raw_data, 0)
        atime = datetime.fromtimestamp(atime_raw, tz=timezone.utc) if atime_raw > 0 else None
        mtime = datetime.fromtimestamp(mtime_raw, tz=timezone.utc) if mtime_raw > 0 else None

        uid, gid = None, None
        if len(raw_data) >= 12:
            uid, gid = struct.unpack_from("<HH", raw_data, 8)

        return DecodedUnix5855(atime=atime, mtime=mtime, uid=uid, gid=gid)

    @staticmethod
    def decode_unicode_path(raw_data: bytes) -> Optional[DecodedUnicodePath]:
        """Decode 0x7075 Info-ZIP Unicode path extra field (Paper Table 5).
        
        Format:
        - 1 byte: Version (1)
        - 4 bytes: CRC32 of standard file name
        - Variable: UTF-8 Unicode file path
        """
        if len(raw_data) < 5:
            return None

        version, name_crc = struct.unpack_from("<BI", raw_data, 0)
        raw_name = raw_data[5:]
        try:
            unicode_path = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            unicode_path = raw_name.decode("utf-8", errors="replace")

        return DecodedUnicodePath(
            version=version,
            name_crc32=name_crc,
            unicode_path=unicode_path,
        )
