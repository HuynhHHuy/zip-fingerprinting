# Provenance Tracker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan. Steps use checkbox syntax for tracking.

**Goal:** Implement PH4-PROV-001 (`ProvenanceTracker`) detecting multi-provenance ZIP archives without decompression.

**Architecture:** Each CDH/LFH pair is fingerprinted independently and classified with the existing
`AutomatedClassifier` (single-entry feature vector). Entries are merged greedily into source groups whose
compatible-environment sets still intersect. More than one group, or mixed host OS, is Case 1 (mixed
fingerprints). An entry whose LFH matches one catalog profile while its CDH matches only different profiles is
a Case 2 LFH/CDH discrepancy (central directory rewritten by SW2, local headers left from SW1).

**Tech Stack:** Python standard library, existing parser/extractor/classifier/rules; pytest.

**Spec:** `docs/project/implementation-plan.md` PH4-PROV-001; paper Section 4.2 and Figure 10;
`docs/research/comprehensive-paper-guide.md` section 6.

## Global Constraints

- Input is `ZipArchiveRecord`; no decompression, no new dependencies, input must not be mutated.
- Reuse `StructuralFeatureExtractor`, `AutomatedClassifier` and `rules.py`; do not alter scientific profiles.
- Legitimate within-tool variation must not be flagged: ASCII vs non-ASCII names (`0x7075` present only for
  non-ASCII names) must stay one source when candidate sets intersect.
- Only HIGH-weight structural evidence (host OS, extra-field sets/order-compatible profiles, `0x5455` lengths,
  data descriptor) sets `is_multi_provenance`. Subsidiary signals (mixed nanosecond patterns) are reported as
  indicators requiring further analysis, never as proof.
- Role labels (original creator vs modifier) are heuristic: the group owning the lowest local-header offset
  is assumed to be SW1 because Add appends entries. Reports must say so.
- Undetectable situations are documented, not guessed: SW2 rewriting every LFH and CDH, or SW1/SW2 whose
  profiles overlap (e.g., Windows 7-Zip vs Bandizip with ASCII names).
- CLI wiring (PH7-CLI-001) and sample generation (PH4-PROV-002) are out of scope.

## Task 1: Tracker and integration tests

**Files:** modify `src/zip_fingerprint/provenance.py`; replace `tests/integration/test_provenance_tracking.py`;
update README/backlog status after verification.

- [x] Write a byte-level ZIP builder in the test with per-entry host OS, LFH/CDH extra fields and descriptor.
- [x] Tests: single-source archives (Windows 7-Zip, WinRAR with mixed ASCII/Korean names, macOS Compress,
  uncatalogued but homogeneous tool), DoD Case 1 (two entries with two fingerprints), Add/Modify scenarios,
  mixed host OS, Case 2 global cascade, partial discrepancy, empty archive, subsidiary nanosecond mixing,
  dict/JSON serialization and no mutation.
- [x] Run tests and confirm failure against the `NotImplementedError` stub.
- [x] Implement tracker; run targeted and complete suites, mypy and black on changed files.
- [x] Record validation results and update project status.

