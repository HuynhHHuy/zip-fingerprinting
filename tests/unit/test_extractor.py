"""Unit tests for StructuralFeatureExtractor."""

import io
import struct
import unicodedata
import pytest
from datetime import datetime, timezone

from zip_fingerprint.constants import (
    EXTRA_HEADER_NTFS,
    EXTRA_HEADER_EXTENDED_TS,
    EXTRA_HEADER_UNIX_UID_GID,
    EXTRA_HEADER_UNICODE_PATH,
    NANO_PATTERN_FULL,
    NANO_PATTERN_WINZIP,
)
from zip_fingerprint.extractor import (
    StructuralFeatureExtractor,
    detect_unicode_normalization,
    dos_to_datetime,
)
from zip_fingerprint.models import (
    CentralDirectoryHeaderRecord,
    EndOfCentralDirectoryRecord,
    ExtraFieldBlock,
    LocalFileHeaderRecord,
    ZipArchiveRecord,
)
from zip_fingerprint.parser import ZipBinaryParser


def test_dos_to_datetime() -> None:
    """Test MS-DOS 32-bit date/time conversion."""
    # 2021-01-11 11:30:58 (seconds resolution = 2s)
    # Time: hr=11 (11 << 11), min=30 (30 << 5), sec=29 (29)
    dos_time = (11 << 11) | (30 << 5) | 29
    # Date: yr=2021-1980=41 (41 << 9), mo=1 (1 << 5), day=11 (11)
    dos_date = (41 << 9) | (1 << 5) | 11

    dt = dos_to_datetime(dos_time, dos_date)
    assert dt is not None
    assert dt.year == 2021
    assert dt.month == 1
    assert dt.day == 11
    assert dt.hour == 11
    assert dt.minute == 30
    assert dt.second == 58


def test_detect_unicode_normalization() -> None:
    """Test detecting NFC vs NFD forms."""
    # Pure ASCII
    assert detect_unicode_normalization(["readme.txt", "data.csv"]) == "ASCII"

    # Korean in NFC form (composed)
    korean_nfc = unicodedata.normalize("NFC", "한글파일.txt")
    assert detect_unicode_normalization([korean_nfc]) == "NFC"

    # Korean in NFD form (decomposed, standard macOS)
    korean_nfd = unicodedata.normalize("NFD", "한글파일.txt")
    assert detect_unicode_normalization([korean_nfd]) == "NFD"


def test_extract_from_minimal_zip(minimal_zip_bytes: bytes) -> None:
    """Test feature extraction from minimal valid in-memory zip."""
    parser = ZipBinaryParser(io.BytesIO(minimal_zip_bytes))
    archive = parser.parse()

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    hw = features["high_weight"]
    sub = features["subsidiary"]

    assert hw["host_os"] == 0  # Windows/DOS
    assert hw["data_descriptor_present"] is False
    assert hw["central_extra_field_ids"] == []

    assert sub["nanosecond_pattern"] == "N/A"
    assert sub["has_macosx_folder"] is False
    assert sub["unicode_normalization"] == "ASCII"
    assert sub["root_folder_header_exists"] is None


def test_extract_winrar_features() -> None:
    """Simulate WinRAR archive on Windows with 0x000A + 0x7075 sequence."""
    # 0x000A block (full nanoseconds)
    ft_precise = 132539328001234567
    raw_ntfs = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft_precise, ft_precise, ft_precise)
    block_ntfs = ExtraFieldBlock(header_id=EXTRA_HEADER_NTFS, data_size=len(raw_ntfs), raw_data=raw_ntfs)

    # 0x7075 block
    raw_up = struct.pack("<BI", 1, 0x12345678) + "한글.txt".encode("utf-8")
    block_up = ExtraFieldBlock(header_id=EXTRA_HEADER_UNICODE_PATH, data_size=len(raw_up), raw_data=raw_up)

    # WinRAR sequence: [0x000A, 0x7075]
    cd_extra = [block_ntfs, block_up]

    cdh_root = CentralDirectoryHeaderRecord(
        offset=100, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=0, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=0, uncompressed_size=0, file_name_length=5, extra_field_length=0,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x10, local_header_offset=0, file_name="set1/", extra_fields=[]
    )
    cdh_file = CentralDirectoryHeaderRecord(
        offset=200, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=0, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=15, extra_field_length=len(raw_ntfs)+len(raw_up)+8,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x20, local_header_offset=50, file_name="set1/한글.txt", extra_fields=cd_extra
    )
    cdh_zip = CentralDirectoryHeaderRecord(
        offset=300, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=0,  # Store -> WinRAR double zipping behavior
        last_mod_time=0, last_mod_date=0, crc32=0, compressed_size=50, uncompressed_size=50,
        file_name_length=14, extra_field_length=0, file_comment_length=0, disk_number_start=0,
        internal_file_attributes=0, external_file_attributes=0x20, local_header_offset=150,
        file_name="set1/inner.zip", extra_fields=[]
    )

    archive = ZipArchiveRecord(
        file_path="sample.zip", file_size=1000,
        eocd=EndOfCentralDirectoryRecord(0, 0, 0, 3, 3, 300, 100, 0),
        central_directory_headers=[cdh_root, cdh_file, cdh_zip],
        local_file_headers=[]
    )

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    hw = features["high_weight"]
    sub = features["subsidiary"]

    assert hw["host_os"] == 0
    assert hw["central_extra_field_sequence"] == [EXTRA_HEADER_NTFS, EXTRA_HEADER_UNICODE_PATH]
    assert sub["nanosecond_pattern"] == NANO_PATTERN_FULL
    assert sub["root_folder_header_exists"] is True
    assert sub["double_zipping"] == "STORED"


def test_extract_winzip_features() -> None:
    """Simulate WinZip archive with reversed sequence [0x7075, 0x000A] and fff0000 nanoseconds."""
    # WinZip truncated nanoseconds (ticks % 10000 == 0)
    ft_winzip = 132539328001230000
    raw_ntfs = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft_winzip, ft_winzip, ft_winzip)
    block_ntfs = ExtraFieldBlock(header_id=EXTRA_HEADER_NTFS, data_size=len(raw_ntfs), raw_data=raw_ntfs)

    raw_up = struct.pack("<BI", 1, 0x12345678) + "한글.txt".encode("utf-8")
    block_up = ExtraFieldBlock(header_id=EXTRA_HEADER_UNICODE_PATH, data_size=len(raw_up), raw_data=raw_up)

    # WinZip sequence: [0x7075, 0x000A]
    cd_extra = [block_up, block_ntfs]

    cdh_file = CentralDirectoryHeaderRecord(
        offset=100, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=8, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=8, extra_field_length=len(raw_ntfs)+len(raw_up)+8,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x20, local_header_offset=0, file_name="한글.txt", extra_fields=cd_extra
    )
    cdh_zip = CentralDirectoryHeaderRecord(
        offset=200, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=8,  # Deflate -> WinZip double zipping behavior
        last_mod_time=0, last_mod_date=0, crc32=0, compressed_size=50, uncompressed_size=100,
        file_name_length=9, extra_field_length=0, file_comment_length=0, disk_number_start=0,
        internal_file_attributes=0, external_file_attributes=0x20, local_header_offset=50,
        file_name="inner.zip", extra_fields=[]
    )

    archive = ZipArchiveRecord(
        file_path="winzip.zip", file_size=1000,
        eocd=EndOfCentralDirectoryRecord(0, 0, 0, 2, 2, 200, 100, 0),
        central_directory_headers=[cdh_file, cdh_zip],
        local_file_headers=[]
    )

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    hw = features["high_weight"]
    sub = features["subsidiary"]

    assert hw["central_extra_field_sequence"] == [EXTRA_HEADER_UNICODE_PATH, EXTRA_HEADER_NTFS]
    assert sub["nanosecond_pattern"] == NANO_PATTERN_WINZIP
    assert sub["double_zipping"] == "RECOMPRESSED"


def test_extract_windows_builtin_missing_root_folder() -> None:
    """Simulate Windows Built-in zip: files inside set1/ but no explicit set1/ entry."""
    cdh_file = CentralDirectoryHeaderRecord(
        offset=100, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=8, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=14, extra_field_length=0,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x20, local_header_offset=0, file_name="set1/file.txt", extra_fields=[]
    )

    archive = ZipArchiveRecord(
        file_path="builtin.zip", file_size=500,
        eocd=EndOfCentralDirectoryRecord(0, 0, 0, 1, 1, 100, 100, 0),
        central_directory_headers=[cdh_file],
        local_file_headers=[]
    )

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    sub = features["subsidiary"]
    assert sub["root_folder_header_exists"] is False


def test_extract_macos_compress_features() -> None:
    """Simulate macOS Archive Utility (GUI Compress): __MACOSX, NFD, UID/GID 501/20, 0x5455 (13 bytes)."""
    # 0x5455: 13 bytes (flags [1] + mtime [4] + atime [4] + ctime [4])
    raw_5455 = struct.pack("<BIII", 0x07, 1600000000, 1600000100, 1600000200)
    block_5455 = ExtraFieldBlock(header_id=EXTRA_HEADER_EXTENDED_TS, data_size=13, raw_data=raw_5455)

    # 0x7875: macOS default UID 501, GID 20
    raw_7875 = struct.pack("<BBHBH", 1, 2, 501, 2, 20)
    block_7875 = ExtraFieldBlock(header_id=EXTRA_HEADER_UNIX_UID_GID, data_size=len(raw_7875), raw_data=raw_7875)

    nfd_korean = unicodedata.normalize("NFD", "한글.txt")

    cdh1 = CentralDirectoryHeaderRecord(
        offset=100, version_made_by=0x031E, extract_version=20, gp_bit_flag=0x0800,
        compression_method=8, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=len(nfd_korean.encode("utf-8")),
        extra_field_length=len(raw_5455)+len(raw_7875)+8,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x81A40000, local_header_offset=0, file_name=nfd_korean,
        extra_fields=[block_5455, block_7875]
    )
    cdh2 = CentralDirectoryHeaderRecord(
        offset=200, version_made_by=0x031E, extract_version=20, gp_bit_flag=0x0800,
        compression_method=0, last_mod_time=0, last_mod_date=0, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=20, extra_field_length=0,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x81A40000, local_header_offset=50,
        file_name="__MACOSX/._test.txt", extra_fields=[]
    )

    lfh1 = LocalFileHeaderRecord(
        offset=0, extract_version=20, gp_bit_flag=0x0808, compression_method=8,
        last_mod_time=0, last_mod_date=0, crc32=0, compressed_size=10, uncompressed_size=10,
        file_name_length=len(nfd_korean.encode("utf-8")), extra_field_length=17,
        file_name=nfd_korean, extra_fields=[block_5455, block_7875], has_data_descriptor=True
    )

    archive = ZipArchiveRecord(
        file_path="macos.zip", file_size=1000,
        eocd=EndOfCentralDirectoryRecord(0, 0, 0, 2, 2, 200, 100, 0),
        central_directory_headers=[cdh1, cdh2],
        local_file_headers=[lfh1]
    )

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    hw = features["high_weight"]
    sub = features["subsidiary"]

    assert hw["host_os"] == 3  # Unix
    assert hw["data_descriptor_present"] is True
    assert hw["central_extra_field_lengths"][EXTRA_HEADER_EXTENDED_TS] == [13]
    assert sub["has_macosx_folder"] is True
    assert sub["unicode_normalization"] == "NFD"
    assert sub["uid"] == 501
    assert sub["gid"] == 20


def test_extract_timezone_offset() -> None:
    """Test timezone calculation between DOS local time and UTC NTFS time."""
    # UTC timestamp: 2021-01-11 12:00:00 UTC
    dt_utc = datetime(2021, 1, 11, 12, 0, 0, tzinfo=timezone.utc)
    unix_time = dt_utc.timestamp()
    ft = int(unix_time * 10_000_000 + 116_444_736_000_000_000)

    raw_ntfs = struct.pack("<IHHQQQ", 0, 0x0001, 24, ft, ft, ft)
    block_ntfs = ExtraFieldBlock(header_id=EXTRA_HEADER_NTFS, data_size=len(raw_ntfs), raw_data=raw_ntfs)

    # DOS local time: 2021-01-11 19:00:00 (which is +7 hours = +420 minutes ahead of UTC)
    dos_time = (19 << 11) | (0 << 5) | 0
    dos_date = (41 << 9) | (1 << 5) | 11

    cdh = CentralDirectoryHeaderRecord(
        offset=100, version_made_by=0x0014, extract_version=20, gp_bit_flag=0,
        compression_method=8, last_mod_time=dos_time, last_mod_date=dos_date, crc32=0,
        compressed_size=10, uncompressed_size=10, file_name_length=8, extra_field_length=len(raw_ntfs)+4,
        file_comment_length=0, disk_number_start=0, internal_file_attributes=0,
        external_file_attributes=0x20, local_header_offset=0, file_name="time.txt",
        extra_fields=[block_ntfs]
    )

    archive = ZipArchiveRecord(
        file_path="tz.zip", file_size=500,
        eocd=EndOfCentralDirectoryRecord(0, 0, 0, 1, 1, 100, 100, 0),
        central_directory_headers=[cdh], local_file_headers=[]
    )

    extractor = StructuralFeatureExtractor(archive)
    features = extractor.extract()

    sub = features["subsidiary"]
    assert sub["timezone_offset_minutes"] == 420  # UTC+7 (Vietnam time)
