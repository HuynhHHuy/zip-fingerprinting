"""Unit tests for ZipBinaryParser."""

import io
import struct
import pytest
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.exceptions import CorruptZipError
from zip_fingerprint.constants import (
    SIG_LOCAL_FILE_HEADER,
    SIG_CENTRAL_DIRECTORY_HEADER,
    SIG_END_OF_CENTRAL_DIRECTORY,
    SIG_DATA_DESCRIPTOR,
)


def test_parser_with_minimal_valid_zip(minimal_zip_bytes: bytes) -> None:
    """Test parsing a valid in-memory ZIP archive."""
    parser = ZipBinaryParser(minimal_zip_bytes)
    archive = parser.parse()

    assert archive.file_path == "<memory>"
    assert archive.file_size == len(minimal_zip_bytes)
    assert archive.eocd.total_entries == 1
    assert archive.eocd.disk_number == 0

    # CDH verification
    assert len(archive.central_directory_headers) == 1
    cdh = archive.central_directory_headers[0]
    assert cdh.file_name == "test.txt"
    assert cdh.crc32 == 0x12345678
    assert cdh.compressed_size == len(b"Hello, Forensics!")
    assert cdh.version_made_by >> 8 == 0  # HostOS = Windows

    # LFH verification
    assert len(archive.local_file_headers) == 1
    lfh = archive.local_file_headers[0]
    assert lfh.file_name == "test.txt"
    assert lfh.crc32 == 0x12345678
    assert not lfh.has_data_descriptor
    assert not archive.has_data_descriptor()


def test_parser_context_manager(minimal_zip_bytes: bytes) -> None:
    """Test ZipBinaryParser used as context manager."""
    with ZipBinaryParser(minimal_zip_bytes) as parser:
        archive = parser.parse()
        assert archive.eocd.total_entries == 1


def test_parser_with_data_descriptor() -> None:
    """Test parsing a ZIP with Data Descriptor (bit 3 set and signature after payload)."""
    buf = io.BytesIO()
    filename = b"streamed.txt"
    data = b"Streaming Deflate Content"
    crc = 0x55667788

    # LFH: crc32, compressed_size, uncompressed_size set to 0, Bit 3 (0x0008) set
    lfh_offset = buf.tell()
    buf.write(
        struct.pack(
            "<IHHHHHIIIHH",
            SIG_LOCAL_FILE_HEADER,
            20,
            0x0008,  # GP bit flag 3 (Data Descriptor present)
            0,
            0x5000,
            0x5000,
            0,  # zeroed in LFH
            0,  # zeroed in LFH
            0,  # zeroed in LFH
            len(filename),
            0,
        )
    )
    buf.write(filename)
    buf.write(data)

    # Data Descriptor: 16 bytes (SIG 4 + CRC 4 + CompSize 4 + UncompSize 4)
    buf.write(struct.pack("<IIII", SIG_DATA_DESCRIPTOR, crc, len(data), len(data)))

    # CDH: contains actual CRC and sizes
    cd_offset = buf.tell()
    buf.write(
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            SIG_CENTRAL_DIRECTORY_HEADER,
            0x0314,  # HostOS = Unix
            20,
            0x0008,  # GP bit flag 3
            0,
            0x5000,
            0x5000,
            crc,
            len(data),
            len(data),
            len(filename),
            0,
            0,
            0,
            0,
            0,
            lfh_offset,
        )
    )
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    # EOCD
    buf.write(
        struct.pack(
            "<IHHHHIIH",
            SIG_END_OF_CENTRAL_DIRECTORY,
            0,
            0,
            1,
            1,
            cd_size,
            cd_offset,
            0,
        )
    )

    archive = ZipBinaryParser(buf.getvalue()).parse()
    assert archive.local_file_headers[0].has_data_descriptor is True
    assert archive.has_data_descriptor() is True


def test_parser_with_extra_fields() -> None:
    """Test parsing ZIP with extra fields in both LFH and CDH."""
    buf = io.BytesIO()

    # Construct dummy extra field: Header 0x000A with 8 bytes payload
    extra_data = struct.pack("<HH8s", 0x000A, 8, b"12345678")
    filename = b"doc.txt"
    data = b"Some data"
    crc = 0xAABBCCDD

    # LFH
    lfh_offset = buf.tell()
    buf.write(
        struct.pack(
            "<IHHHHHIIIHH",
            SIG_LOCAL_FILE_HEADER,
            20,
            0,
            0,
            0x5000,
            0x5000,
            crc,
            len(data),
            len(data),
            len(filename),
            len(extra_data),
        )
    )
    buf.write(filename)
    buf.write(extra_data)
    buf.write(data)

    # CDH
    cd_offset = buf.tell()
    buf.write(
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            SIG_CENTRAL_DIRECTORY_HEADER,
            0x0314,  # HostOS = 3 (Unix)
            20,
            0,
            0,
            0x5000,
            0x5000,
            crc,
            len(data),
            len(data),
            len(filename),
            len(extra_data),
            0,
            0,
            0,
            0,
            lfh_offset,
        )
    )
    buf.write(filename)
    buf.write(extra_data)
    cd_size = buf.tell() - cd_offset

    # EOCD
    buf.write(
        struct.pack(
            "<IHHHHIIH",
            SIG_END_OF_CENTRAL_DIRECTORY,
            0,
            0,
            1,
            1,
            cd_size,
            cd_offset,
            0,
        )
    )

    archive = ZipBinaryParser(buf.getvalue()).parse()
    assert len(archive.central_directory_headers[0].extra_fields) == 1
    cd_ef = archive.central_directory_headers[0].extra_fields[0]
    assert cd_ef.header_id == 0x000A
    assert cd_ef.data_size == 8
    assert cd_ef.raw_data == b"12345678"

    assert len(archive.local_file_headers[0].extra_fields) == 1
    lf_ef = archive.local_file_headers[0].extra_fields[0]
    assert lf_ef.header_id == 0x000A
    assert lf_ef.data_size == 8


def test_parser_corrupt_zip_short_file() -> None:
    """Test parser raises CorruptZipError on file too short."""
    with pytest.raises(CorruptZipError, match="too small"):
        ZipBinaryParser(b"PK\x05\x06short").parse()


def test_parser_corrupt_zip_no_eocd() -> None:
    """Test parser raises CorruptZipError when EOCD signature is missing."""
    with pytest.raises(CorruptZipError, match="not found"):
        ZipBinaryParser(b"A" * 100).parse()


def test_parser_nonexistent_file() -> None:
    """Test parser raises FileNotFoundError when file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        ZipBinaryParser("non_existent_file.zip").parse()
