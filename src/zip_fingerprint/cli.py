"""Command-line interface (CLI) for ZIP fingerprinting and provenance tracking."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import List, Optional

from zip_fingerprint.classifier import AutomatedClassifier
from zip_fingerprint.exceptions import ZipFingerprintError
from zip_fingerprint.extractor import StructuralFeatureExtractor
from zip_fingerprint.hasher import build_canonical_fingerprint
from zip_fingerprint.parser import ZipBinaryParser


def compute_file_sha256(path: Path) -> str:
    """Compute standard SHA-256 digest of entire archive file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_output(zip_path: Path, output: Optional[str], text: str) -> int:
    """Write a report without overwriting its source or leaking stream errors."""
    try:
        if output:
            out_path = Path(output)
            if out_path.exists() and out_path.samefile(zip_path):
                sys.stderr.write("Error: Output file must not be the input ZIP or an alias.\n")
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

    # Subcommand: decompress-check
    dec_parser = subparsers.add_parser(
        "decompress-check", help="Evaluate decompression timestamp artifacts against Table 8"
    )
    dec_parser.add_argument(
        "--bmac", type=str, required=True, help="Observed BMAC pattern (e.g. EEER, RERR, HHHR)"
    )

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
    elif args.subcommand in ("provenance", "decompress-check"):
        msg = f"Error: Subcommand '{args.subcommand}' is not yet implemented (PH7-CLI-001/B).\n"
        sys.stderr.write(msg)
        return 1
    else:
        sys.stderr.write(f"Error: Unknown subcommand '{args.subcommand}'.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
