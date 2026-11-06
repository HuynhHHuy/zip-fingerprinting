"""Decompression artifact and timestamp reversal analyzer.

Reference:
    Minji Um et al. (2021), Section 4.3 & Table 8:
    Timestamp records when a given ZIP file was decompressed on Windows (BMAC order).
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

_DECOMPRESSORS = ("WinRAR", "WinZip", "7-Zip", "Bandizip", "Compressed folder")

# Table 8, PDF page 9. Columns follow _DECOMPRESSORS; each string is B-M-A-C.
# None means no extra field, not an absent directory header. The latter has its
# own entry type. These are historical experimental profiles, not universal rules.
_TABLE_8: Dict[Tuple[str, Optional[int]], Tuple[str, ...]] = {
    ("file", None): ("RHRR", "HHHR", "RHRR", "RHRR", "HHHR"),
    ("file", 0x000A): ("RERR", "EEER", "EEER", "EEER", "HHHR"),
    ("file", 0x5455): ("RERR", "HHHR", "RERR", "RHRR", "HHHR"),
    ("file", 0x5855): ("RHRR", "HHHR", "REER", "RHRR", "HHHR"),
    ("folder_no_header", None): ("RRRR", "RRRR", "RRRR", "RRRR", "RRRR"),
    ("folder_with_files", None): ("RHRR", "HRRR", "RHRR", "RRRR", "RRRR"),
    ("folder_with_files", 0x000A): ("RERR", "ERRR", "EEER", "ERRR", "RRRR"),
    ("folder_with_files", 0x5455): ("RERR", "HRRR", "RERR", "RRRR", "RRRR"),
    ("folder_with_files", 0x5855): ("RHRR", "HRRR", "REER", "RRRR", "RRRR"),
    ("empty_folder", None): ("RHRR", "HHHR", "RHRR", "RHRR", "RHRR"),
    ("empty_folder", 0x000A): ("RERR", "EEER", "EEER", "EEER", "RHRR"),
    ("empty_folder", 0x5455): ("RERR", "HHHR", "RERR", "RHRR", "RHRR"),
    ("empty_folder", 0x5855): ("RHRR", "HHHR", "REER", "RHRR", "RHRR"),
}

_ENTRY_TYPES = {
    "file": "file",
    "folder_with_files": "folder_with_files",
    "empty_folder": "empty_folder",
    "folder_no_header": "folder_no_header",
    # Literal state labels in Table 8, for the original evaluate_bmac_pattern API.
    "contains file(s)": "folder_with_files",
    "empty": "empty_folder",
    "no header": "folder_no_header",
}


class DecompressionAnalyzer:
    """Look up historical Windows profiles and flag timestamp ordering anomalies.

    Inputs already describe timestamp sources (R/H/E), not measured timestamps.
    Candidate matches and reversal warnings alone do not establish attribution
    or tampering. Filesystem measurement is a separate experiment.
    """

    def identify_decompressor(
        self,
        observed_bmac: str,
        entry_type: str,
        extra_field: Union[int, str, None] = None,
    ) -> List[str]:
        """Return every matching Table 8 candidate in column order.

        Entry types: file, folder_with_files, empty_folder, folder_no_header.
        Extra fields accept integer IDs, 0x-prefixed hex strings, or None/"None".
        "N/A" is valid only for folder_no_header. Patterns ignore whitespace/case.
        Invalid syntax/context raises ValueError; unsupported patterns/IDs return [].
        """
        pattern = "".join(observed_bmac.upper().split())
        if len(pattern) != 4 or set(pattern) - {"R", "H", "E"}:
            raise ValueError("BMAC must contain four R/H/E symbols in B-M-A-C order")
        state = _ENTRY_TYPES.get(entry_type.strip().lower())
        if state is None:
            raise ValueError(f"Unknown entry type: {entry_type}")
        header: Optional[int]
        if isinstance(extra_field, str):
            text = extra_field.strip().lower()
            if text == "none" or (text == "n/a" and state == "folder_no_header"):
                header = None
            elif text.startswith("0x"):
                try:
                    header = int(text, 16)
                except ValueError as exc:
                    raise ValueError(f"Invalid extra field: {extra_field}") from exc
            else:
                raise ValueError(f"Invalid extra field: {extra_field}")
        else:
            header = extra_field
        if header is not None and (
            isinstance(header, bool) or not isinstance(header, int) or not 0 <= header <= 0xFFFF
        ):
            raise ValueError("Extra field ID must be an unsigned 16-bit integer")
        if state == "folder_no_header" and header is not None:
            raise ValueError("A folder without a header cannot have an extra field")
        row = _TABLE_8.get((state, header), ())
        return [tool for tool, expected in zip(_DECOMPRESSORS, row) if pattern == expected]

    def evaluate_bmac_pattern(self, bmac_pattern: str, state: str, header_id: str) -> List[str]:
        """Compatibility wrapper; state accepts canonical types or table state labels."""
        return self.identify_decompressor(bmac_pattern, state, header_id)

    def check_time_reversal(
        self,
        parent_folder_time: Optional[datetime] = None,
        subfolder_time: Optional[datetime] = None,
        creation_time: Optional[datetime] = None,
        mod_time: Optional[datetime] = None,
    ) -> List[str]:
        """Return ordering warnings for available datetime pairs, in stable order.

        Missing pairs are not assessed. Folder inputs must refer to the same
        timestamp attribute (e.g. both modification times). Naive values assume
        one shared clock; aware values compare UTC instants. Mixed awareness in
        a pair raises ValueError. Equality does not constitute reversal.
        An empty result can mean either no reversal or insufficient observations.
        """
        pairs = (
            (mod_time, creation_time, "CREATION_AFTER_MODIFICATION"),
            (subfolder_time, parent_folder_time, "SUBFOLDER_BEFORE_PARENT"),
        )
        warnings = []
        for earlier, later, code in pairs:
            for value in (earlier, later):
                if value is not None and not isinstance(value, datetime):
                    raise TypeError("Timestamp values must be datetime or None")
            if earlier is None or later is None:
                continue
            earlier_aware = earlier.utcoffset() is not None
            later_aware = later.utcoffset() is not None
            if earlier_aware != later_aware:
                raise ValueError("Both timestamps in a pair must use consistent timezone awareness")
            if earlier_aware:
                earlier = earlier.astimezone(timezone.utc)
                later = later.astimezone(timezone.utc)
            if earlier < later:
                warnings.append(code)
        return warnings
