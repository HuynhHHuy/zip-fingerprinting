"""Generate reproducible Figure 5 replacement payloads (PH6-DATA-001).

Only atime/mtime are fixed, not creation/change time. These synthetic payloads
are not the authors' original files or ground-truth archiver samples.
"""

import argparse
import hashlib
import io
from itertools import chain
import json
import os
from pathlib import Path
import stat
from typing import Dict, List, Set, Tuple
import unicodedata
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXED_NS = 1610364659000000000  # 2021-01-11 11:30:59 UTC
# DOS ZIP timestamps cannot represent odd seconds. No timezone conversion.
ZIP_TIME = (2021, 1, 11, 11, 30, 58)


def _zip_bytes(entries: List[Tuple[str, bytes]]) -> bytes:
    """Fix all ZIP metadata and avoid compressor-version-dependent output."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.create_system = 0
            info.create_version = 20
            info.extract_version = 20
            info.external_attr = 0x20
            archive.writestr(info, payload)
    return buffer.getvalue()


def _payloads() -> Dict[str, bytes]:
    jpeg = (ROOT / "scripts/fixtures/corpus.jpg").read_bytes()
    document = _zip_bytes(
        [
            (
                "[Content_Types].xml",
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                b'<Default Extension="rels" '
                b'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                b'<Default Extension="xml" ContentType="application/xml"/>'
                b'<Override PartName="/word/document.xml" '
                b'ContentType="application/vnd.openxmlformats-officedocument.'
                b'wordprocessingml.document.main+xml"/>'
                b"</Types>",
            ),
            (
                "_rels/.rels",
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b"<Relationships "
                b'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                b'<Relationship Id="rId1" '
                b'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                b'relationships/officeDocument" Target="word/document.xml"/>'
                b"</Relationships>",
            ),
            (
                "word/document.xml",
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b"<w:document "
                b'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b"<w:body><w:p><w:r><w:t>Standard forensics test content.</w:t></w:r></w:p>"
                b'<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr></w:body></w:document>',
            ),
        ]
    )
    korean = "가나다"
    return {
        "set1/Study/capture.JPG": jpeg,
        "set1/Study/Sample.docx": document,
        "set1/Study/textsm.txt": b"Standard forensics test content.\n",
        "set1/2021.JPG": jpeg,
        f"auxiliary/korean_nfc/{korean}.txt": (korean + "\n").encode("utf-8"),
        f"auxiliary/korean_nfd/{unicodedata.normalize('NFD', korean)}.txt": (korean + "\n").encode(
            "utf-8"
        ),
        "auxiliary/encodings/korean-cp949.txt": (korean + "\n").encode("cp949"),
        "auxiliary/vietnamese/tiếng-Việt.txt": "Tiếng Việt\n".encode("utf-8"),
        "auxiliary/double_zip/inner.zip": _zip_bytes([("nested.txt", b"Nested ZIP fixture.\n")]),
    }


def _check_existing(target: Path, directories: Set[str], files: Set[str]) -> None:
    """Reject links, wrong types and unknown data before modifying any file."""
    ancestors = list(reversed(target.parents)) + [target]
    # Iterate lazily so a directory link is rejected before traversing it.
    existing = target.rglob("*") if target.is_dir() else ()
    for path in chain(ancestors, existing):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(f"Refusing link/reparse point: {path}")
        if path in ancestors:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"Expected directory: {path}")
            continue
        relative = path.relative_to(target).as_posix()
        if relative in directories and stat.S_ISDIR(info.st_mode):
            continue
        if relative in files and stat.S_ISREG(info.st_mode):
            if info.st_nlink == 1:
                continue
            raise ValueError(f"Refusing hard link: {path}")
        raise ValueError(f"Unexpected path or file type: {path}")


def _set_times(path: Path) -> None:
    os.utime(path, ns=(FIXED_NS, FIXED_NS))
    info = path.stat()
    if info.st_atime_ns != FIXED_NS or info.st_mtime_ns != FIXED_NS:
        raise ValueError(f"Filesystem did not retain exact atime/mtime: {path}")


def create_standard_corpus(target_dir: Path) -> None:
    """Generate fixed payloads and a manifest; refuse unknown existing data.

    Re-running restores owned files and timestamps. No files are deleted.
    Reads/copies/checkouts may change timestamps; regenerate before experiments.
    """
    target = Path(os.path.abspath(target_dir))
    payloads = _payloads()
    directories = {"set1/emptyFolder"}
    for name in payloads:
        directories.update(p.as_posix() for p in Path(name).parents if p != Path("."))
    _check_existing(target, directories, set(payloads) | {"manifest.json"})
    entries: List[Dict[str, object]] = []
    for name in sorted(directories | payloads.keys()):
        if name in directories:
            entries.append({"path": name, "type": "directory"})
        else:
            data = payloads[name]
            entries.append(
                {
                    "path": name,
                    "type": "file",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    manifest = {
        "schema_version": 1,
        "description": (
            "Synthetic Figure 5 replacements plus separate auxiliary cases; not paper ground truth."
        ),
        "timestamp_utc": "2021-01-11T11:30:59Z",
        "timestamp_fields": ["atime", "mtime"],
        "timestamp_exclusions": ["creation_time", "change_time"],
        "zip_timestamp": "2021-01-11T11:30:58 (DOS, no timezone)",
        "entries": entries,
    }
    payloads["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    for name in sorted(directories):
        (target / name).mkdir(parents=True, exist_ok=True)
    for name, data in payloads.items():
        (target / name).write_bytes(data)
    # Also catches filesystems that silently normalize requested Unicode names.
    _check_existing(target, directories, set(payloads))
    # Hashes came from memory; set times after all writes and directory edits.
    for name in payloads:
        _set_times(target / name)
    for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        _set_times(target / name)
    _set_times(target)
    print(f"Standard corpus successfully created at: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "data/templates")
    args = parser.parse_args()
    try:
        create_standard_corpus(args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Corpus generation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
