"""Run the project's parser and extractor on the author's reference samples (PH0-REF-002).

For every sample in the manifest this script:
  1. checks the bytes against the manifest SHA-256;
  2. parses them with ZipBinaryParser and StructuralFeatureExtractor;
  3. checks a few structural claims of the paper that do not depend on the classifier
     (host OS byte, root folder header, __MACOSX, data descriptor, WinZip nanoseconds,
     per-entry order of 0x000A / 0x7075 in the central directory);
  4. records the classifier's top candidates next to the filename label.

The paper checks judge the filename labels; they are not classifier accuracy (#22).

Usage:
    python experiments/analyze_author_samples.py [--samples DIR] [--output FILE]
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zip_fingerprint.classifier import AutomatedClassifier  # noqa: E402
from zip_fingerprint.extractor import StructuralFeatureExtractor  # noqa: E402
from zip_fingerprint.models import ZipArchiveRecord  # noqa: E402
from zip_fingerprint.parser import ZipBinaryParser  # noqa: E402

DEFAULT_MANIFEST = ROOT / "data" / "reference" / "author_pkzip" / "manifest.json"
DEFAULT_SAMPLES = ROOT / "data" / "reference" / "author_pkzip" / "samples"
DEFAULT_OUTPUT = ROOT / "results" / "classifications" / "author_pkzip_analysis.json"

NTFS = 0x000A
UNICODE_PATH = 0x7075

Check = Dict[str, Any]


def _check(name: str, expected: Any, observed: Any, source: str) -> Check:
    if expected is None:
        status = "not_applicable"
    else:
        status = "consistent" if observed == expected else "inconsistent"
    return {
        "check": name,
        "expected": expected,
        "observed": observed,
        "status": status,
        "source": source,
    }


def central_orders(archive: ZipArchiveRecord) -> List[List[str]]:
    """Distinct per-entry orders of NTFS / Unicode Path IDs in the central directory."""
    orders: List[List[str]] = []
    for cdh in archive.central_directory_headers:
        ids = [b.header_id for b in cdh.extra_fields if b.header_id in (NTFS, UNICODE_PATH)]
        if UNICODE_PATH not in ids:
            continue
        order = [f"0x{i:04X}" for i in ids]
        if order not in orders:
            orders.append(order)
    return orders


def paper_checks(
    label: Dict[str, str], features: Dict[str, Any], archive: ZipArchiveRecord
) -> List[Check]:
    os_name, app = label["os"], label["application"]
    hw, sub = features["high_weight"], features["subsidiary"]
    windows = os_name == "Windows"
    checks = [
        _check(
            "host_os_byte",
            0 if windows else 3,
            hw["host_os"],
            "Algorithm 2: version made by 0x00 (Windows) / 0x03 (Unix)",
        ),
        _check(
            "root_folder_header",
            (app != "Compressed folder") if windows else None,
            sub["root_folder_header_exists"],
            "Section 3.2.1: only Compressed folder omits the root folder header",
        ),
        _check(
            "macosx_folder",
            (app == "Compress") if os_name == "macOS" else False,
            sub["has_macosx_folder"],
            "Section 3.3.1: __MACOSX only from macOS Compress",
        ),
        _check(
            "data_descriptor",
            {"Compress": True, "zip": False}.get(app) if not windows else None,
            hw["data_descriptor_present"],
            "Section 3.3.2: Compress writes data descriptors, zip does not",
        ),
    ]
    nano_expected: Optional[str] = None
    if windows and app == "WinZip":
        nano_expected = "fff0000"
    elif windows and app in ("WinRAR", "7-Zip", "Bandizip"):
        nano_expected = "fffffff"
    checks.append(
        _check(
            "ntfs_nanoseconds",
            nano_expected,
            sub["nanosecond_pattern"],
            "Section 3.1.1 / Table 6: WinZip rounds to fff0000",
        )
    )
    orders = central_orders(archive)
    order_expected: Optional[List[List[str]]] = None
    if windows and orders:
        if app == "WinZip":
            order_expected = [["0x7075", "0x000A"]]
        elif app in ("WinRAR", "Bandizip"):
            order_expected = [["0x000A", "0x7075"]]
    checks.append(
        _check(
            "central_extra_order_with_unicode_path",
            order_expected,
            orders,
            "Section 3.1.3 / Table 6: WinRAR & Bandizip 0x000A->0x7075, WinZip 0x7075->0x000A",
        )
    )
    return checks


def classifier_top(features: Dict[str, Any]) -> Tuple[Optional[float], List[str]]:
    candidates = AutomatedClassifier().classify(features)
    if not candidates:
        return None, []
    best = max(c.confidence for c in candidates)
    tops = [f"{c.target_os}/{c.application}" for c in candidates if c.confidence == best]
    return best, sorted(tops)


def analyze_sample(sample: Dict[str, Any], data: bytes) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "id": sample["id"],
        "path": sample["path"],
        "label": sample["label"],
        "label_basis": sample["label_basis"],
    }
    if hashlib.sha256(data).hexdigest() != sample["sha256"]:
        record["status"] = "checksum_mismatch"
        return record
    parser = ZipBinaryParser(data)
    try:
        archive = parser.parse()
    finally:
        parser.close()
    features = StructuralFeatureExtractor(archive).extract()
    hw, sub = features["high_weight"], features["subsidiary"]
    checks = paper_checks(sample["label"], features, archive)
    best, tops = classifier_top(features)
    label = f"{sample['label']['os']}/{sample['label']['application']}"
    record.update(
        {
            "status": "parsed",
            "entries": features["summary"]["total_entries"],
            "features": {
                "host_os": hw["host_os"],
                "data_descriptor_present": hw["data_descriptor_present"],
                "local_extra_field_ids": [f"0x{i:04X}" for i in hw["local_extra_field_ids"]],
                "central_extra_field_ids": [f"0x{i:04X}" for i in hw["central_extra_field_ids"]],
                "central_extra_field_sequence_feature": [
                    f"0x{i:04X}" for i in hw["central_extra_field_sequence"]
                ],
                "central_orders_with_unicode_path": central_orders(archive),
                "nanosecond_pattern": sub["nanosecond_pattern"],
                "filename_encoding": sub["filename_encoding"],
                "unicode_normalization": sub["unicode_normalization"],
                "has_macosx_folder": sub["has_macosx_folder"],
                "root_folder_header_exists": sub["root_folder_header_exists"],
                "uid": sub["uid"],
                "gid": sub["gid"],
                "timezone_offset_minutes": sub["timezone_offset_minutes"],
            },
            "paper_checks": checks,
            "paper_inconsistencies": [c["check"] for c in checks if c["status"] == "inconsistent"],
            "classifier": {
                "top_confidence": best,
                "top_candidates": tops,
                "unique_top_matches_label": tops == [label],
                "label_among_top": label in tops,
            },
        }
    )
    return record


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    parsed = [r for r in records if r["status"] == "parsed"]
    return {
        "samples": len(records),
        "parsed": len(parsed),
        "labels_without_paper_inconsistency": sum(
            1 for r in parsed if not r["paper_inconsistencies"]
        ),
        "classifier_unique_top_matches_label": sum(
            1 for r in parsed if r["classifier"]["unique_top_matches_label"]
        ),
        "classifier_label_among_top": sum(1 for r in parsed if r["classifier"]["label_among_top"]),
        "note": "Diagnostic run on 17 filename-labelled samples; not the #22 evaluation.",
    }


def run(manifest_path: Path, samples_dir: Path) -> Dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records: List[Dict[str, Any]] = []
    for sample in manifest["samples"]:
        path = samples_dir / sample["path"]
        if not path.is_file():
            records.append({"id": sample["id"], "path": sample["path"], "status": "missing"})
            continue
        records.append(analyze_sample(sample, path.read_bytes()))
    return {
        "task": "PH0-REF-002",
        "source": manifest["source"],
        "summary": summarize(records),
        "samples": records,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Any = None) -> int:
    args = build_parser().parse_args(argv)
    report = run(args.manifest, args.samples)
    if report["summary"]["parsed"] == 0:
        print("Error: no sample parsed; run scripts/fetch_author_samples.py", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
