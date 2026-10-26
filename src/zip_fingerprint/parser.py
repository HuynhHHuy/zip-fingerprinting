"""Binary parser for raw ZIP archives without extracting payload."""

import io
import struct
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, List, Optional, Type, Union

from zip_fingerprint.constants import (
    SIG_LOCAL_FILE_HEADER,
    SIG_CENTRAL_DIRECTORY_HEADER,
    SIG_END_OF_CENTRAL_DIRECTORY,
    SIG_DATA_DESCRIPTOR,
    SIG_ZIP64_EOCD_RECORD,
    SIG_ZIP64_EOCD_LOCATOR,
)
from zip_fingerprint.models import (
    ExtraFieldBlock,
    LocalFileHeaderRecord,
    CentralDirectoryHeaderRecord,
    EndOfCentralDirectoryRecord,
    ZipArchiveRecord,
)
from zip_fingerprint.extra_fields import ExtraFieldParser
from zip_fingerprint.exceptions import CorruptZipError


def parse_raw_extra_field_blocks(raw_bytes: bytes) -> List[ExtraFieldBlock]:
    """Parse raw extra field buffer into individual ExtraFieldBlock entries."""
    return ExtraFieldParser.parse_blocks(raw_bytes)


class ZipBinaryParser:
    """Zero-extraction binary parser reading only headers, metadata, and extra fields.
    
    Adheres strictly to Minji Um et al. (2021) Section 3:
    - Traverses from EOCD -> Central Directory -> Local File Headers
    - Does NOT decompress payload (preserving payload integrity and forensic soundness)
    - Detects Data Descriptor signatures and bit flags
    """

    def __init__(self, file_path_or_bytes: Union[str, Path, bytes, BinaryIO]):
        self.stream: BinaryIO
        self.file_size: int
        self._should_close = False
        self.file_path = "<memory>"

        if isinstance(file_path_or_bytes, bytes):
            self.stream = io.BytesIO(file_path_or_bytes)
            self.file_size = len(file_path_or_bytes)
        elif hasattr(file_path_or_bytes, "read") and hasattr(file_path_or_bytes, "seek"):
            self.stream = file_path_or_bytes  # type: ignore[assignment]
            current_pos = self.stream.tell()
            self.stream.seek(0, io.SEEK_END)
            self.file_size = self.stream.tell()
            self.stream.seek(current_pos)
            self.file_path = getattr(file_path_or_bytes, "name", "<stream>")
            self._should_close = False
        else:
            self.file_path = str(file_path_or_bytes)
            path_obj = Path(file_path_or_bytes)
            if not path_obj.exists():
                raise FileNotFoundError(f"ZIP file not found: {self.file_path}")
            self.file_size = path_obj.stat().st_size
            self.stream = open(path_obj, "rb")
            self._should_close = True

    def __enter__(self) -> "ZipBinaryParser":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._should_close and hasattr(self, "stream") and not self.stream.closed:
            self.stream.close()

    def parse(self) -> ZipArchiveRecord:
        """Parse the ZIP file and return structured records."""
        try:
            eocd = self._find_and_parse_eocd()
            cd_headers = self._parse_central_directory(eocd)
            local_headers = self._parse_local_headers(cd_headers)

            return ZipArchiveRecord(
                file_path=self.file_path,
                file_size=self.file_size,
                eocd=eocd,
                central_directory_headers=cd_headers,
                local_file_headers=local_headers,
            )
        finally:
            self.close()

    def _find_and_parse_eocd(self) -> EndOfCentralDirectoryRecord:
        """Locate and parse End of Central Directory record from the end of file."""
        # Minimum EOCD is 22 bytes. Max comment is 65535 bytes -> scan window up to 65535 + 22 bytes.
        scan_size = min(self.file_size, 65535 + 22)
        if scan_size < 22:
            raise CorruptZipError(f"File size {self.file_size} is too small to be a valid ZIP archive.")

        self.stream.seek(self.file_size - scan_size)
        data = self.stream.read(scan_size)

        # Signature: 0x06054B50 -> bytes b"PK\x05\x06"
        eocd_pos = data.rfind(b"PK\x05\x06")
        if eocd_pos == -1:
            raise CorruptZipError("End of Central Directory signature (0x06054B50) not found.")

        absolute_offset = self.file_size - scan_size + eocd_pos
        self.stream.seek(absolute_offset)
        eocd_raw = self.stream.read(22)
        if len(eocd_raw) < 22:
            raise CorruptZipError("Truncated End of Central Directory record.")

        (
            sig,
            disk_number,
            cd_start_disk,
            num_entries_this_disk,
            total_entries,
            cd_size,
            cd_start_offset,
            comment_length,
        ) = struct.unpack("<IHHHHIIH", eocd_raw)

        if sig != SIG_END_OF_CENTRAL_DIRECTORY:
            raise CorruptZipError(f"Invalid EOCD signature: 0x{sig:08X}")

        comment = b""
        if comment_length > 0:
            comment = self.stream.read(comment_length)

        return EndOfCentralDirectoryRecord(
            offset=absolute_offset,
            disk_number=disk_number,
            cd_start_disk=cd_start_disk,
            num_entries_this_disk=num_entries_this_disk,
            total_entries=total_entries,
            cd_size=cd_size,
            cd_start_offset=cd_start_offset,
            comment_length=comment_length,
            comment=comment,
        )

    def _parse_central_directory(
        self, eocd: EndOfCentralDirectoryRecord
    ) -> List[CentralDirectoryHeaderRecord]:
        """Parse all Central Directory Header records."""
        cd_headers: List[CentralDirectoryHeaderRecord] = []
        self.stream.seek(eocd.cd_start_offset)

        for _ in range(eocd.total_entries):
            current_offset = self.stream.tell()
            cdh_raw = self.stream.read(46)
            if len(cdh_raw) < 46:
                raise CorruptZipError(
                    f"Truncated Central Directory Header at offset 0x{current_offset:X}."
                )

            (
                sig,
                version_made_by,
                extract_version,
                gp_bit_flag,
                compression_method,
                last_mod_time,
                last_mod_date,
                crc32,
                compressed_size,
                uncompressed_size,
                file_name_length,
                extra_field_length,
                file_comment_length,
                disk_number_start,
                internal_file_attributes,
                external_file_attributes,
                local_header_offset,
            ) = struct.unpack("<IHHHHHHIIIHHHHHII", cdh_raw)

            if sig != SIG_CENTRAL_DIRECTORY_HEADER:
                raise CorruptZipError(
                    f"Invalid Central Directory Header signature 0x{sig:08X} at 0x{current_offset:X}."
                )

            # Read variable fields
            raw_file_name = self.stream.read(file_name_length)
            raw_extra_field = self.stream.read(extra_field_length)
            raw_comment = self.stream.read(file_comment_length)

            # Decode file name (try UTF-8 first, fallback to cp437)
            try:
                file_name = raw_file_name.decode("utf-8")
            except UnicodeDecodeError:
                file_name = raw_file_name.decode("cp437", errors="replace")

            extra_blocks = parse_raw_extra_field_blocks(raw_extra_field)

            cd_headers.append(
                CentralDirectoryHeaderRecord(
                    offset=current_offset,
                    version_made_by=version_made_by,
                    extract_version=extract_version,
                    gp_bit_flag=gp_bit_flag,
                    compression_method=compression_method,
                    last_mod_time=last_mod_time,
                    last_mod_date=last_mod_date,
                    crc32=crc32,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    file_name_length=file_name_length,
                    extra_field_length=extra_field_length,
                    file_comment_length=file_comment_length,
                    disk_number_start=disk_number_start,
                    internal_file_attributes=internal_file_attributes,
                    external_file_attributes=external_file_attributes,
                    local_header_offset=local_header_offset,
                    file_name=file_name,
                    extra_fields=extra_blocks,
                    file_comment=raw_comment,
                )
            )

        return cd_headers

    def _parse_local_headers(
        self, cd_headers: List[CentralDirectoryHeaderRecord]
    ) -> List[LocalFileHeaderRecord]:
        """Parse Local File Headers corresponding to Central Directory entries."""
        local_headers: List[LocalFileHeaderRecord] = []

        for cdh in cd_headers:
            self.stream.seek(cdh.local_header_offset)
            current_offset = self.stream.tell()
            lfh_raw = self.stream.read(30)
            if len(lfh_raw) < 30:
                raise CorruptZipError(
                    f"Truncated Local File Header at offset 0x{current_offset:X} for {cdh.file_name}."
                )

            (
                sig,
                extract_version,
                gp_bit_flag,
                compression_method,
                last_mod_time,
                last_mod_date,
                crc32,
                compressed_size,
                uncompressed_size,
                file_name_length,
                extra_field_length,
            ) = struct.unpack("<IHHHHHIIIHH", lfh_raw)

            if sig != SIG_LOCAL_FILE_HEADER:
                raise CorruptZipError(
                    f"Invalid Local File Header signature 0x{sig:08X} at 0x{current_offset:X} for {cdh.file_name}."
                )

            raw_file_name = self.stream.read(file_name_length)
            raw_extra_field = self.stream.read(extra_field_length)

            try:
                file_name = raw_file_name.decode("utf-8")
            except UnicodeDecodeError:
                file_name = raw_file_name.decode("cp437", errors="replace")

            extra_blocks = parse_raw_extra_field_blocks(raw_extra_field)

            # Determine Data Descriptor presence
            # Bit 3 of general purpose bit flag indicates CRC and sizes are zero in LFH
            # and placed in data descriptor following compressed data.
            has_data_desc = bool(gp_bit_flag & 0x0008)

            # Also scan for Data Descriptor signature (0x08074B50) immediately following compressed data
            data_end_offset = (
                current_offset + 30 + file_name_length + extra_field_length + cdh.compressed_size
            )
            if data_end_offset + 4 <= self.file_size:
                self.stream.seek(data_end_offset)
                sig_candidate = self.stream.read(4)
                if sig_candidate == struct.pack("<I", SIG_DATA_DESCRIPTOR):
                    has_data_desc = True

            local_headers.append(
                LocalFileHeaderRecord(
                    offset=current_offset,
                    extract_version=extract_version,
                    gp_bit_flag=gp_bit_flag,
                    compression_method=compression_method,
                    last_mod_time=last_mod_time,
                    last_mod_date=last_mod_date,
                    crc32=crc32,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    file_name_length=file_name_length,
                    extra_field_length=extra_field_length,
                    file_name=file_name,
                    extra_fields=extra_blocks,
                    has_data_descriptor=has_data_desc,
                )
            )

        return local_headers
