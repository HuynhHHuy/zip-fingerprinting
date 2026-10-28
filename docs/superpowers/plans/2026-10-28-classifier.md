# Automated Classifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan. Steps use checkbox syntax for tracking.

**Goal:** Implement PH3-CLF-002 using the existing extractor, rule catalog and CandidateEnvironment model.

**Architecture:** Algorithm 1 matches descriptor presence, paired local/central extra-field sets and known 0x5455 lengths. Algorithm 2 filters by host OS. A unique structural/OS match returns HIGH/1.0; otherwise Algorithm 3 ranks all compatible candidates using subsidiary evidence and retains ties.

**Tech Stack:** Python standard library and existing pytest; no application dependencies added.

**Spec:** `docs/project/implementation-plan.md`, PH3-CLF-002; local paper PDF, section 4.1 and Figures 7–8 (visually inspected).

## Global Constraints

- Preserve `classify(features) -> List[CandidateEnvironment]` and extractor dictionary format.
- Expose `estimate_program_1`, `estimate_program_2`, `estimate_program_3` as testable stages.
- Consume existing `rules.py`; do not change scientific profiles to satisfy tests.
- Missing critical evidence, unsupported signatures/OS, empty archives or mixed host OS return no candidates rather than inventing a source.
- Unknown subsidiary values (`None`, ASCII, DEFAULT, N/A, NO_NESTED_ZIP) supply no evidence.
- Input dictionaries must not be mutated; integer or decimal-string length keys work.
- Confidence for subsidiary results is a documented heuristic, never a calibrated probability.
- CLI wiring, provenance, decompression, dataset generation and remote publication are outside this task.

## Decisions

The backlog supplies the accepted design and user explicitly requested its implementation.
Figure 8 collects features but does not define numeric scoring; the backlog requests
weighted ranking, so this implementation supplies that policy transparently.

Weights: non-ASCII extra-field variant, central extra-field order, nanoseconds, UID/GID and nested-ZIP behavior = 3;
Unicode normalization, CP949 and __MACOSX presence = 2; root header and alphabetical
order = 1. Skip criteria with unknown observations or no expected value in a profile.
Score = `round(0.5 + 0.49 * (matched_weight - conflicting_weight) / observed_weight, 6)`;
use 0.5 if no comparable evidence. All subsidiary results stay below 1.0. Preserve
all high-compatible candidates, ordered by score descending then OS/application.
Record matches and conflicts and annotate ties/insufficient evidence. For ASCII
archives, project a rule's Unicode extra-field order onto the actually present IDs.
For observed NFC/NFD, also compare paired LFH/CDH sets to the profile's Unicode
variant (or base if no distinct variant exists). Keep this in Algorithm 3 so
target-dependent Unicode evidence never produces a HIGH/1.0 match.

## Review Focus

- Insufficient evidence must not be interpreted as evidence for Compressed folder.
- Windows/macOS/Ubuntu profile overlap must retain ambiguity without arbitrary winners.
- Unknown and contradictory low-weight signals must not override high-weight filtering.
- JSON key conversion and actual extractor output must work without schema changes.
- All 12 theoretical profiles need explicit independent expected results; no generated rule-to-rule oracle.

## Task 1: Classifier and real tests

**Files:** modify `src/zip_fingerprint/classifier.py`, replace `tests/integration/test_classifier_algorithms.py`; update README and backlog status after verification.

**Interfaces:** consumes extractor `high_weight`, `subsidiary`, `summary` and existing rule catalog; produces ranked CandidateEnvironment objects.

- [x] Add parameterized fixtures with explicit Table 6/7 observations for all 12 profiles and expected top environments.
- [x] Add stage tests, HIGH short circuit, subsidiary ambiguity/conflict, unknown values, empty/mixed/unsupported inputs, JSON key roundtrip and actual parser/extractor integration.
- [x] Run classifier tests and confirm failure against the existing NotImplementedError stub.
- [x] Implement the three stages and orchestration; run targeted and complete test suites.
- [x] Run focused mypy and formatting checks on changed Python files, inspect classifier coverage, and request an independent review.
- [x] Record exact validation results and update project status without implying empirical accuracy on real corpora. Commit locally on the feature branch.

## Validation and review results

- Baseline: 36 passed. Initial RED run: 28 new classifier cases failed against the stub.
- Final suite: 76 passed on Windows/Python 3.11.9, including 41 classifier cases.
- Classifier statement coverage: 100%; package statement coverage: 89%.
- Focused mypy (`--follow-imports=silent`), Black check and whitespace check pass.
- Independent review found one Important gap: non-ASCII Windows 7-Zip remained tied
  with Bandizip. A regression test reproduced it, then the Unicode-variant evidence
  criterion fixed it without moving the result to HIGH or discarding candidates.
- Review also found mislabeled CP949 evidence. Assertions reproduced the incorrect
  metadata; output now records actual CP949/UTF-8 encoding values.
- All three regression failures were observed before the fixes; the complete suite
  passed afterward. No unresolved review findings.
- Python 3.10, Ubuntu hosted runners and empirical ZIP accuracy remain unverified
  in this local task. No push or PR performed.
