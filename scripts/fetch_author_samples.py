"""Fetch the author's reference ZIP samples from Software Heritage (PH0-REF-002).

The original repository (github.com/um2inji/PKZIP) is gone; Software Heritage keeps
an archived copy. The repository has no license, so the bytes are never committed:
this script downloads them into a git-ignored folder and checks every file against
the manifest (size, git blob id and SHA-256) before keeping it.

Usage:
    python scripts/fetch_author_samples.py [--manifest PATH] [--dest DIR]
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "reference" / "author_pkzip" / "manifest.json"
DEFAULT_DEST = ROOT / "data" / "reference" / "author_pkzip" / "samples"
API = "https://archive.softwareheritage.org/api/1"
USER_AGENT = "zip-fingerprint-reference-fetch/1.0"


class VerificationError(Exception):
    """Raised when downloaded bytes do not match the manifest."""


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def verify(sample: Dict[str, Any], data: bytes) -> None:
    if len(data) != sample["size"]:
        raise VerificationError(f"{sample['id']}: size {len(data)} != {sample['size']}")
    if git_blob_id(data) != sample["sha1_git"]:
        raise VerificationError(f"{sample['id']}: sha1_git mismatch")
    if hashlib.sha256(data).hexdigest() != sample["sha256"]:
        raise VerificationError(f"{sample['id']}: sha256 mismatch")


def download(sha1_git: str, attempts: int = 4) -> bytes:
    url = f"{API}/content/sha1_git:{sha1_git}/raw/"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return bytes(response.read())
        except OSError as exc:
            if attempt == attempts:
                raise
            print(f"retry {attempt}/{attempts} for {sha1_git}: {exc}", file=sys.stderr)
            time.sleep(5 * attempt)
    raise AssertionError("unreachable")


def load_manifest(path: Path) -> Dict[str, Any]:
    manifest: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return manifest


def fetch(manifest: Dict[str, Any], dest: Path) -> List[Path]:
    written: List[Path] = []
    for sample in manifest["samples"]:
        target = dest / sample["path"]
        if target.is_file():
            try:
                verify(sample, target.read_bytes())
                print(f"cached {sample['path']}")
                written.append(target)
                continue
            except VerificationError:
                print(f"stale {sample['path']}, downloading again", file=sys.stderr)
        data = download(sample["sha1_git"])
        verify(sample, data)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f"ok {sample['path']}")
        written.append(target)
    return written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    return parser


def main(argv: Any = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        files = fetch(load_manifest(args.manifest), args.dest)
    except VerificationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: download failed: {exc}", file=sys.stderr)
        return 1
    print(f"{len(files)} samples verified in {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
