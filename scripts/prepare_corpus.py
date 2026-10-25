"""Prepare standard sample corpus based on Figure 5 of Um et al. (2021).

Cấu trúc mục tiêu theo Hình 5:
set1/
├── Study/
│   ├── capture.JPG
│   ├── Sample.docx
│   └── textsm.txt
├── emptyFolder/
└── 2021.JPG
"""

import sys
from pathlib import Path


def create_standard_corpus(target_dir: Path) -> None:
    """Generate fixed corpus tree with deterministic timestamps."""
    study_dir = target_dir / "set1" / "Study"
    empty_dir = target_dir / "set1" / "emptyFolder"
    study_dir.mkdir(parents=True, exist_ok=True)
    empty_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy files
    (study_dir / "capture.JPG").write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 64)
    (study_dir / "Sample.docx").write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    (study_dir / "textsm.txt").write_text("Standard forensics test content.", encoding="utf-8")
    (target_dir / "set1" / "2021.JPG").write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 64)

    print(f"Standard corpus successfully created at: {target_dir}")


if __name__ == "__main__":
    base_dir = Path("data/templates")
    create_standard_corpus(base_dir)

