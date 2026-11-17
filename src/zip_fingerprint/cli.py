"""Command-line interface (CLI) for ZIP fingerprinting and provenance tracking."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import List, Optional, Sequence, Union

from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.decompression import DecompressionAnalyzer
from zip_fingerprint.exceptions import ZipFingerprintError
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.hasher import build_canonical_fingerprint
from zip_fingerprint.parser import ZipBinaryParser
from zip_fingerprint.provenance import ProvenanceTracker


def compute_file_sha256(path: Path) -> str:
    """Compute standard SHA-256 digest of entire archive file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_output(
    source_paths: Union[Path, Sequence[Path], None],
    output: Optional[str],
    text: str,
) -> int:
    """Write a report without overwriting its sources or leaking stream errors."""
    try:
        if output:
            out_path = Path(output)
            if out_path.exists():
                paths: Sequence[Path]
                if source_paths is None:
                    paths = []
                elif isinstance(source_paths, Path):
                    paths = [source_paths]
                else:
                    paths = list(source_paths)
                for src in paths:
                    if src.exists() and out_path.samefile(src):
                        sys.stderr.write(
                            "Error: Output file must not be an input ZIP or an alias.\n"
                        )
                        return 1
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
        else:
            encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            safe_text = text.encode(encoding, errors="backslashreplace").decode(encoding)
            sys.stdout.write(safe_text)
            sys.stdout.flush()
    except (OSError, UnicodeError) as exc:
        if not output:
            # Prevent Python retrying a failed buffered flush during shutdown.
            try:
                with open(os.devnull, "w") as sink:
                    os.dup2(sink.fileno(), sys.stdout.fileno())
            except (OSError, ValueError):
                pass  # In-memory streams may not have a file descriptor.
        destination = f"output file '{output}'" if output else "stdout"
        sys.stderr.write(f"Error writing {destination}: {exc}\n")
        return 1
    return 0


def handle_fingerprint(args: argparse.Namespace) -> int:
    """Execute 'fingerprint' subcommand."""
    zip_path = Path(args.zip_path)
    if not zip_path.exists():
        sys.stderr.write(f"Error: Target ZIP file does not exist: '{args.zip_path}'\n")
        return 1
    if not zip_path.is_file():
        sys.stderr.write(f"Error: Target path is not a regular file: '{args.zip_path}'\n")
        return 1

    try:
        content_hash = compute_file_sha256(zip_path)
        with ZipBinaryParser(zip_path) as parser:
            archive = parser.parse()
        extractor = StructuralFeatureExtractor(archive)
        features = extractor.extract()
        canonical_fp = build_canonical_fingerprint(features, sha256_content=content_hash)
        output_json = json.dumps(canonical_fp.model_dump(mode="json"), indent=2, ensure_ascii=True)
    except (ZipFingerprintError, OSError) as e:
        sys.stderr.write(f"Error analyzing ZIP file: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error analyzing ZIP file: {e}\n")
        return 1

    return _write_output(zip_path, args.output, output_json + "\n")


def handle_identify(args: argparse.Namespace) -> int:
    """Execute 'identify' subcommand."""
    zip_path = Path(args.zip_path)
    if not zip_path.exists():
        sys.stderr.write(f"Error: Target ZIP file does not exist: '{args.zip_path}'\n")
        return 1
    if not zip_path.is_file():
        sys.stderr.write(f"Error: Target path is not a regular file: '{args.zip_path}'\n")
        return 1

    try:
        content_hash = compute_file_sha256(zip_path)
        with ZipBinaryParser(zip_path) as parser:
            archive = parser.parse()
        extractor = StructuralFeatureExtractor(archive)
        features = extractor.extract()
        canonical_fp = build_canonical_fingerprint(features, sha256_content=content_hash)

        classifier = AutomatedClassifier()
        candidates = classifier.classify(features)
    except (ZipFingerprintError, OSError) as e:
        sys.stderr.write(f"Error analyzing ZIP file: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error analyzing ZIP file: {e}\n")
        return 1

    format_type = getattr(args, "format", "json")
    if format_type == "text":
        lines = [
            f"Target: {args.zip_path}",
            f"Structural Hash: {canonical_fp.structural_hash}",
            f"Archive SHA-256: {content_hash}",
            f"Total Candidates: {len(candidates)}",
        ]
        if not candidates:
            lines.append("No compatible environment found in catalog (unknown or mixed structure).")
        else:
            for idx, c in enumerate(candidates, start=1):
                rules_str = ", ".join(c.matched_rules) if c.matched_rules else "None"
                notes_str = "; ".join(c.notes) if c.notes else "None"
                lines.append(
                    f"Candidate {idx}:\n"
                    f"  Target OS:     {c.target_os}\n"
                    f"  Application:   {c.application}\n"
                    f"  Confidence:    {c.confidence:.2f}\n"
                    f"  Weight Tier:   {c.weight_tier}\n"
                    f"  Matched Rules: {rules_str}\n"
                    f"  Notes:         {notes_str}"
                )
        rendered_output = "\n".join(lines) + "\n"
    else:
        result_payload = {
            "file_path": str(zip_path),
            "structural_hash": canonical_fp.structural_hash,
            "archive_sha256": content_hash,
            "total_candidates": len(candidates),
            "candidates": [
                {
                    "target_os": c.target_os,
                    "application": c.application,
                    "confidence": c.confidence,
                    "weight_tier": c.weight_tier,
                    "matched_rules": c.matched_rules,
                    "notes": c.notes,
                }
                for c in candidates
            ],
        }
        rendered_output = json.dumps(result_payload, indent=2, ensure_ascii=True) + "\n"

    return _write_output(zip_path, getattr(args, "output", None), rendered_output)


def handle_provenance(args: argparse.Namespace) -> int:
    """Execute 'provenance' subcommand."""
    zip_path = Path(args.zip_path)
    if not zip_path.exists():
        sys.stderr.write(f"Error: Target ZIP file does not exist: '{args.zip_path}'\n")
        return 1
    if not zip_path.is_file():
        sys.stderr.write(f"Error: Target path is not a regular file: '{args.zip_path}'\n")
        return 1

    try:
        with ZipBinaryParser(zip_path) as parser:
            archive = parser.parse()
        tracker = ProvenanceTracker(archive)
        report = tracker.analyze()
        report_data = {
            "file_path": str(zip_path),
            **report.to_dict(),
        }
    except (ZipFingerprintError, OSError) as e:
        sys.stderr.write(f"Error analyzing ZIP file: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error analyzing ZIP file: {e}\n")
        return 1

    format_type = getattr(args, "format", "json")
    if format_type == "text":
        lines = [
            f"Target: {args.zip_path}",
            f"Multi-Provenance:           {report.is_multi_provenance}",
            f"Requires Further Analysis:  {report.requires_further_analysis}",
            f"Case 1 (Mixed Fingerprints): {report.case1_detected}",
            f"Case 2 (Cascade Rewrite):    {report.case2_detected}",
            f"Total Groups:               {len(report.groups)}",
            f"Total Indicators:           {len(report.indicators)}",
            f"Total Suspected Apps:       {len(report.suspected_applications)}",
        ]
        if report.suspected_applications:
            lines.append("Suspected Applications:")
            for s in report.suspected_applications:
                lines.append(f"  - {s.target_os} {s.application} ({s.role}): {s.basis}")
        if report.indicators:
            lines.append("Indicators:")
            for ind in report.indicators:
                lines.append(f"  - [{ind.weight}] {ind.code}: {ind.detail}")
        if report.limitations:
            lines.append("Limitations:")
            for lim in report.limitations:
                lines.append(f"  - {lim}")
        rendered_output = "\n".join(lines) + "\n"
    else:
        rendered_output = json.dumps(report_data, indent=2, ensure_ascii=True) + "\n"

    return _write_output(zip_path, getattr(args, "output", None), rendered_output)


def handle_decompress_check(args: argparse.Namespace) -> int:
    """Execute 'decompress-check' subcommand."""
    analyzer = DecompressionAnalyzer()
    try:
        candidates = analyzer.identify_decompressor(
            observed_bmac=args.bmac,
            entry_type=args.entry_type,
            extra_field=args.extra_field,
        )
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        return 1

    format_type = getattr(args, "format", "json")
    if format_type == "text":
        lines = [
            f"Observed BMAC:    {args.bmac}",
            f"Entry Type:       {args.entry_type}",
            f"Extra Field:      {args.extra_field or 'None'}",
            f"Total Candidates: {len(candidates)}",
        ]
        if not candidates:
            lines.append("No matching decompressor found in Table 8 catalog.")
        else:
            lines.append("Candidates:")
            for idx, c in enumerate(candidates, start=1):
                lines.append(f"  {idx}. {c}")
        rendered_output = "\n".join(lines) + "\n"
    else:
        result_payload = {
            "observed_bmac": args.bmac,
            "entry_type": args.entry_type,
            "extra_field": args.extra_field,
            "total_candidates": len(candidates),
            "candidates": candidates,
        }
        rendered_output = json.dumps(result_payload, indent=2, ensure_ascii=True) + "\n"

    return _write_output(None, getattr(args, "output", None), rendered_output)


def handle_compare(args: argparse.Namespace) -> int:
    """Execute 'compare' subcommand."""
    zip_path1 = Path(args.zip_path1)
    zip_path2 = Path(args.zip_path2)

    for p, arg_name in ((zip_path1, args.zip_path1), (zip_path2, args.zip_path2)):
        if not p.exists():
            sys.stderr.write(f"Error: Target ZIP file does not exist: '{arg_name}'\n")
            return 1
        if not p.is_file():
            sys.stderr.write(f"Error: Target path is not a regular file: '{arg_name}'\n")
            return 1

    try:
        content_hash1 = compute_file_sha256(zip_path1)
        with ZipBinaryParser(zip_path1) as parser1:
            archive1 = parser1.parse()
        extractor1 = StructuralFeatureExtractor(archive1)
        features1 = extractor1.extract()
        canonical_fp1 = build_canonical_fingerprint(features1, sha256_content=content_hash1)
    except (ZipFingerprintError, OSError) as e:
        sys.stderr.write(f"Error analyzing ZIP file '{args.zip_path1}': {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error analyzing ZIP file '{args.zip_path1}': {e}\n")
        return 1

    try:
        content_hash2 = compute_file_sha256(zip_path2)
        with ZipBinaryParser(zip_path2) as parser2:
            archive2 = parser2.parse()
        extractor2 = StructuralFeatureExtractor(archive2)
        features2 = extractor2.extract()
        canonical_fp2 = build_canonical_fingerprint(features2, sha256_content=content_hash2)
    except (ZipFingerprintError, OSError) as e:
        sys.stderr.write(f"Error analyzing ZIP file '{args.zip_path2}': {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Unexpected error analyzing ZIP file '{args.zip_path2}': {e}\n")
        return 1

    # Diff the same feature groups that compute_structural_hash hashes. The
    # schema projection drops raw subsidiary keys such as uid/gid/double_zipping.
    hw1 = features1["high_weight"]
    hw2 = features2["high_weight"]
    diff_hw = []
    for key in sorted(hw1.keys()):
        val1 = hw1[key]
        val2 = hw2.get(key)
        if val1 != val2:
            diff_hw.append({"feature": key, "target1": val1, "target2": val2})

    sub1 = features1["subsidiary"]
    sub2 = features2["subsidiary"]
    diff_sub = []
    for key in sorted(sub1.keys()):
        val1 = sub1[key]
        val2 = sub2.get(key)
        if val1 != val2:
            diff_sub.append({"feature": key, "target1": val1, "target2": val2})

    structural_match = canonical_fp1.structural_hash == canonical_fp2.structural_hash

    format_type = getattr(args, "format", "json")
    if format_type == "text":
        lines = [
            f"Target 1: {args.zip_path1}",
            f"  Structural Hash: {canonical_fp1.structural_hash}",
            f"  Archive SHA-256: {content_hash1}",
            f"Target 2: {args.zip_path2}",
            f"  Structural Hash: {canonical_fp2.structural_hash}",
            f"  Archive SHA-256: {content_hash2}",
            f"Structural Match:   {structural_match}",
        ]
        if structural_match:
            lines.append("No structural differences found.")
        else:
            lines.append("Differences:")
            for d in diff_hw:
                lines.append(f"  [high_weight] {d['feature']}: {d['target1']} != {d['target2']}")
            for d in diff_sub:
                lines.append(f"  [subsidiary]  {d['feature']}: {d['target1']} != {d['target2']}")
        rendered_output = "\n".join(lines) + "\n"
    else:
        payload = {
            "target1": {
                "file_path": str(zip_path1),
                "structural_hash": canonical_fp1.structural_hash,
                "archive_sha256": content_hash1,
            },
            "target2": {
                "file_path": str(zip_path2),
                "structural_hash": canonical_fp2.structural_hash,
                "archive_sha256": content_hash2,
            },
            "equal": structural_match,
            "structural_match": structural_match,
            "total_differences": len(diff_hw) + len(diff_sub),
            "differences": {
                "high_weight": diff_hw,
                "subsidiary": diff_sub,
            },
        }
        rendered_output = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

    return _write_output([zip_path1, zip_path2], getattr(args, "output", None), rendered_output)


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(
        prog="zip-fingerprint",
        description="Forensic analysis and provenance tracking of ZIP archives.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Subcommand: fingerprint
    fp_parser = subparsers.add_parser("fingerprint", help="Generate structural fingerprint JSON")
    fp_parser.add_argument("zip_path", type=str, help="Path to target ZIP file")
    fp_parser.add_argument("--output", "-o", type=str, help="Path to write JSON output")

    # Subcommand: identify
    id_parser = subparsers.add_parser("identify", help="Classify source OS and compression tool")
    id_parser.add_argument("zip_path", type=str, help="Path to target ZIP file")
    id_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    id_parser.add_argument("--output", "-o", type=str, help="Path to write output")

    # Subcommand: provenance
    prov_parser = subparsers.add_parser(
        "provenance", help="Analyze modification history and multi-environment traces"
    )
    prov_parser.add_argument("zip_path", type=str, help="Path to target ZIP file")
    prov_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    prov_parser.add_argument("--output", "-o", type=str, help="Path to write output")

    # Subcommand: decompress-check
    dec_parser = subparsers.add_parser(
        "decompress-check", help="Evaluate decompression timestamp artifacts against Table 8"
    )
    dec_parser.add_argument(
        "--bmac", type=str, required=True, help="Observed BMAC pattern (e.g. EEER, RERR, HHHR)"
    )
    dec_parser.add_argument(
        "--entry-type",
        type=str,
        default="file",
        help="Entry type: file, folder_with_files, empty_folder, folder_no_header (default: file)",
    )
    dec_parser.add_argument(
        "--extra-field",
        type=str,
        default=None,
        help="Extra field ID (e.g. 0x000A, 0x5455, 0x5855, None, N/A)",
    )
    dec_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    dec_parser.add_argument("--output", "-o", type=str, help="Path to write output")

    # Subcommand: compare
    comp_parser = subparsers.add_parser(
        "compare", help="Compare forensic structural features between two ZIP archives"
    )
    comp_parser.add_argument("zip_path1", type=str, help="Path to first ZIP file")
    comp_parser.add_argument("zip_path2", type=str, help="Path to second ZIP file")
    comp_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    comp_parser.add_argument("--output", "-o", type=str, help="Path to write output")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "fingerprint":
        return handle_fingerprint(args)
    elif args.subcommand == "identify":
        return handle_identify(args)
    elif args.subcommand == "provenance":
        return handle_provenance(args)
    elif args.subcommand == "decompress-check":
        return handle_decompress_check(args)
    elif args.subcommand == "compare":
        return handle_compare(args)
    else:
        sys.stderr.write(f"Error: Unknown subcommand '{args.subcommand}'.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
