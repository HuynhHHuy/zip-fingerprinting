"""Command-line interface (CLI) for ZIP fingerprinting and provenance tracking."""

import argparse
import sys
from typing import List, Optional


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

    # Subcommand: provenance
    prov_parser = subparsers.add_parser("provenance", help="Analyze modification history and multi-environment traces")
    prov_parser.add_argument("zip_path", type=str, help="Path to target ZIP file")

    # Subcommand: decompress-check
    dec_parser = subparsers.add_parser("decompress-check", help="Evaluate decompression timestamp artifacts against Table 8")
    dec_parser.add_argument("--bmac", type=str, required=True, help="Observed BMAC pattern (e.g. EEER, RERR, HHHR)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    print(f"Command '{args.subcommand}' will be executed once core modules are implemented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

