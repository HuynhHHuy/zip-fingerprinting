"""Binary parser for raw ZIP archives without extracting payload."""

from pathlib import Path
from typing import BinaryIO
from zip_fingerprint.models import ZipArchiveRecord, EndOfCentralDirectoryRecord
from zip_fingerprint.exceptions import CorruptZipError


class ZipBinaryParser:
    """Parses raw ZIP file binary structures (EOCD, CDH, LFH) deterministically."""

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)

    def parse(self) -> ZipArchiveRecord:
        """Parse the ZIP file and return structured records.
        
        To be fully implemented in Task CORE-002.
        """
        raise NotImplementedError("Parsing logic will be implemented in CORE-002.")

