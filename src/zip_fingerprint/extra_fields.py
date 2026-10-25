"""Parser and decoder for ZIP Extra Field blocks."""

from typing import Dict, Any, List
from zip_fingerprint.models import ExtraFieldBlock


class ExtraFieldParser:
    """Decodes Extra Field payloads (0x000A, 0x5455, 0x7875, 0x5855, 0x7075)."""

    @staticmethod
    def parse_blocks(raw_bytes: bytes) -> List[ExtraFieldBlock]:
        """Split raw extra field byte buffer into individual blocks."""
        raise NotImplementedError("Extra field block splitting implemented in CORE-003.")

