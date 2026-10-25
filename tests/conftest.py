"""Shared fixtures for testing ZIP structures and synthetic archives."""

import pytest
import io
import struct
from zip_fingerprint.constants import (
    SIG_LOCAL_FILE_HEADER,
    SIG_CENTRAL_DIRECTORY_HEADER,
    SIG_END_OF_CENTRAL_DIRECTORY,
)


@pytest.fixture
def minimal_zip_bytes() -> bytes:
    """Generate a minimal valid raw ZIP archive in memory for testing."""
    buf = io.BytesIO()
    
    # 1. Local File Header
    lfh_offset = buf.tell()
    filename = b"test.txt"
    data = b"Hello, Forensics!"
    crc = 0x12345678
    
    # LFH: 30 bytes
    buf.write(struct.pack(
        "<IHHHHHIIIHH",
        SIG_LOCAL_FILE_HEADER,
        20,        # extract version
        0,         # gp bit flag
        0,         # compression method (Store)
        0x5000,    # mod time
        0x5000,    # mod date
        crc,
        len(data), # compressed size
        len(data), # uncompressed size
        len(filename),
        0          # extra field length
    ))
    buf.write(filename)
    buf.write(data)
    
    # 2. Central Directory Header
    cd_offset = buf.tell()
    buf.write(struct.pack(
        "<IHHHHHHIIIHHHHHII",
        SIG_CENTRAL_DIRECTORY_HEADER,
        0x0014,    # version made by (Host OS = 0 Windows/FAT, Zip spec 2.0)
        20,        # extract version
        0,         # gp bit flag
        0,         # method
        0x5000,    # time
        0x5000,    # date
        crc,
        len(data),
        len(data),
        len(filename),
        0,         # extra field length
        0,         # comment length
        0,         # disk start
        0,         # internal attr
        0x00000020,# external attr
        lfh_offset
    ))
    buf.write(filename)
    cd_size = buf.tell() - cd_offset
    
    # 3. EOCD
    buf.write(struct.pack(
        "<IHHHHIIH",
        SIG_END_OF_CENTRAL_DIRECTORY,
        0,         # disk number
        0,         # cd disk
        1,         # entries this disk
        1,         # total entries
        cd_size,
        cd_offset,
        0          # comment length
    ))
    
    return buf.getvalue()

