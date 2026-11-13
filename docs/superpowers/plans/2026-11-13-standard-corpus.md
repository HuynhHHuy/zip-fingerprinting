# PH6-DATA-001 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan. The user approved the scope and acceptance criteria in the preceding repository review; execute inline without another approval round.

**Goal:** Generate a valid, reproducible Figure 5 corpus and separate supplementary cases.

**Architecture:** Retain `create_standard_corpus(target_dir: Path) -> None` and add an argparse `--output` option. Use stdlib ZIP/XML, a fixed JPEG fixture, explicit ZIP metadata, SHA-256 and `os.utime(ns=...)`. Keep generated data and its deterministic manifest in `data/templates/`.

**Tech Stack:** Python 3.10+, stdlib in the generator; Pillow in development tests for independent JPEG decoding.

**Spec:** `docs/project/implementation-plan.md`, PH6-DATA-001, and the user-approved acceptance criteria in the repository review.

## Global Constraints

- Base `set1/` exactly matches Figure 5; additional cases live under `auxiliary/`.
- Fixed filesystem atime/mtime: `2021-01-11 11:30:59 UTC` (`1610364659000000000` ns).
- Do not promise fixed creation/change times. ZIP DOS timestamps have two-second precision.
- Synthetic replacement payloads are not the authors' original files or experimental ground truth.
- No commits; preserve existing unrelated/untracked files and modified-sample runs.

## Review Focus

- Repeated generation and generation into different paths: identical files and manifest.
- Existing unrelated data and symbolic links/reparse points: refuse before writing; never delete.
- Unicode normalization on different filesystems: NFC/NFD names in separate directories.
- Reads can update atime: set timestamps after hashing/writing; test stat before payload reads.
- ZIP output varies by host/time: explicitly fix timestamps, ordering, platform and attributes; use STORE.

## Task 1: Corpus generator, tests and documentation

**Files:** `scripts/prepare_corpus.py`, `scripts/fixtures/corpus.jpg`, `tests/unit/test_prepare_corpus.py`, `pyproject.toml`, `data/templates/manifest.json`, `data/README.md`, README and task status.

- [x] Write tests for exact base tree, real JPEG decoding/OOXML relationships, fixed timestamps, auxiliary encodings/nested ZIP, manifest inventory/checksums, reruns, CLI and safe refusal.
- [x] Run `python -m pytest tests/unit/test_prepare_corpus.py -p no:cacheprovider`; observe failures against the old implementation.
- [x] Implement the minimal generator and immutable JPEG fixture. Add Pillow only to dev dependencies.
- [x] Run focused tests, generate the default corpus and independently open the DOCX/JPEG.
- [x] Document timestamp/encoding/reproduction limits and update the backlog based on verified results.
- [x] Run full pytest, mypy, Black/Flake8 on changed Python, and `git diff --check`; request a fresh review.

## Execution evidence

- Starting HEAD: `6304bd7`; tracked files clean. Existing two untracked presentation files preserved.
- Ruling: execute in the existing feature checkout, consistent with the approved follow-up; do not create a worktree or commit.
- RED: initial tests found missing timestamps, auxiliary cases, manifest, CLI output handling and data protection; a separate JPEG decoding test and junction-refusal test also failed against the original implementation.
- Ruling: directory enumeration updates atime on this host. Tests stat the independently specified paths before enumerating; generation sets/verifies times after inventory and payload operations.
- GREEN: 8 focused tests passed; full suite 141 passed, no skips (Windows/Python 3.11.9).
- Mypy: no issues in 16 source files (`src` plus generator); Black/Flake8 changed Python and diff whitespace checks passed. Dependency integrity check passed.
- Independent opening: python-docx read the expected paragraph; Pillow decoded the JPEG as 16x16 RGB with the expected color.
- Fresh read-only review: no actionable findings; additional hard-link refusal check preserved the outside file. Concurrency attacks, transactional output and unverified platforms remain outside the documented local-generator scope.
