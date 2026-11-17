# Native Case 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Request one final independent review.

**Goal:** Prepare and verify a native Bandizip 7.x -> Explorer Delete experiment for #19, preserving negative findings.

**Architecture:** Add a focused evidence reader/comparator and a prepare/finalize CLI beside the existing simulator. Keep the existing simulator API and MoveHere scenarios unchanged. Desktop automation operates only the generated working archive; it is not disguised as a process log or baked into package CLI.

**Tech Stack:** Python stdlib, existing parser/tracker, pytest, native Bandizip portable and Explorer.

**Spec:** `docs/superpowers/specs/2026-11-17-native-case2-design.md` (approved 18/11/2026).

## Global constraints

- Current Windows, Bandizip 7.x portable; at most default and one isolated Unicode-Path configuration. No historical VM escalation.
- Fresh run directories, immutable baseline, source checksums, no edits to shared corpus/catalogue or existing samples.
- Do not change associations/system code page/timezone/security settings. Record executable source/version/SHA/signature.
- Native Case 1 + global Case 2 needed for DoD; synthetic tests/operator assertions do not establish native GUI evidence. Negative results keep #19 open.
- Keep JSON authoritative and atomically saved; package evidence outside Git with checksums, scientific limits and accessible handoff.

## Review focus

1. Unicode identity/collision and conflicting LFH/CDH names: strict evidence-backed decoding, reject ambiguity (Task 1).
2. Offset/timestamp-only changes accidentally passing Case 2: explicit qualifying fields and scope (Task 1).
3. Unsafe archive/run paths, reparse points and oversized payload reads: reject before modification/decompression (Tasks 1/2).
4. Incomplete/mislabelled GUI evidence or concurrent archive writes: preserve pending/failure; freeze only completed GUI output (Task 2).
5. Broken native process/baseline mutation/repeated finalize: preserve diagnostics and refuse overwrites (Task 2).

## Task 1 — Bounded ZIP evidence and structural comparison

**Files:** create `experiments/modification_evidence.py`, `tests/unit/test_modification_evidence.py`.

**Interfaces:** `read_evidence(path: Path, encoding: str) -> dict`; `compare_delete(before: dict, after: dict, target: str = "target.txt") -> dict`.

- [ ] Write tests: unchanged/valid delete, payload corruption/wrong deletion, all vs partial qualifying rewrites, timestamp-only and relocation-only false, duplicate/path/link/size rejection, UTF-8/CRC-valid Unicode Path/legacy lossless names and LFH/CDH conflict.
- [ ] Run `python -B -m pytest -p no:cacheprovider tests/unit/test_modification_evidence.py`; observe RED.
- [ ] Read parser headers and raw name/extra bytes from a bounded snapshot, validate with ZipFile CRC/payload reads by entry object. Cap archive and total uncompressed bytes at 16 MiB; reject encrypted/non-regular entries, unsupported type, duplicate and malformed/ambiguous names.
- [ ] Store every scalar LFH/CDH field, raw header/name/extra bytes and payload SHA. Qualifying changes: version fields, compression method, UTF8/descriptor flag bits, raw filename encoding and extra ID/order/length layout. Raw timestamp values/offsets/CRC/sizes alone are not qualifying. Return changed/qualifying fields per survivor, all/partial/none scope and payload validation independent of tracker.
- [ ] Run tests GREEN, relevant mypy/Black/Flake8, commit.

## Task 2 — Prepare/finalize experiment workflow

**Files:** create `experiments/explorer_delete.py`, `tests/integration/test_explorer_delete.py`.

**Interfaces:** `prepare(output: Path, executable: Path, configuration: str = "default") -> dict`; `finalize(run: Path, gui_log: Path) -> dict`; `main(argv: list[str] | None = None) -> int`.

- [ ] Write tests for unique runs, invalid/missing executable/process failure, prepared anchors, failed CRC/payload, wrong deletion, incomplete/path-mismatched GUI log, operator-only negative DoD, repeated finalize, baseline changes, reparse/foreign run paths. Separate real Bandizip integration skip from synthetic contract tests.
- [ ] Observe RED with the integration test module before implementation.
- [ ] CLI: `python -m experiments.explorer_delete prepare --bandizip PATH [--output PATH] [--configuration default|unicode-path]`; `finalize RUN --gui-log PATH`. Default output `data/modified_samples/`; schema1 plus explicit workflow marker/run ID/absolute run path.
- [ ] Reuse simulator run/version/SHA helpers and atomic JSON helper. Source: target.txt, keep.txt, Vietnamese and Korean survivors with fixed atime/mtime. Before/after names exact; manifest payload SHA/size, baseline hash, environment/ACP and commands saved before awaiting GUI.
- [ ] Failed runs persist reason/commands; source/baseline anchors retained. Reject links/reparse and unexpected top-level state/path, accept finalize only awaiting state. Verify GUI log workflow/run/path/target/app/action/start/end and evidence files/checksums; operator-only stays unverified. Do not claim logs are cryptographically unforgeable.
- [ ] Require operator-confirmed closed archive and unchanged snapshot checksums around read/copy; copy to new `observed-after.zip`, never overwrite prior frozen evidence. Compare and analyze both ZIPs using tracker, retain independent rewrite scope vs tracker disagreement. Final status positive/negative/failed, GUI verification separate; no Case 2 from tracker alone. JSON + readable field table; repeated finalization refuses mutation.
- [ ] Exit0 finalized valid observation,1 error,2 prepared/pending or valid observation without Case2 when requested. Native success must not skip if tool exists but fails.
- [ ] Run GREEN and full suite/static checks; commit.

## Task 3 — Native observations and evidence handoff

**Files:** update `docs/research/modification-simulator.md`, `docs/evaluation/reproduction_report.md`, `docs/project/implementation-plan.md`, README; add small evidence manifest/summary.

- [ ] Download official portable archive, record provenance/hash/signature; use private tool directory, inspect portable behavior and help. Do not redistribute proprietary binaries in Git/evidence.
- [ ] Generate fresh native Case1 via existing control-add. Prepare Bandizip default, perform actual Explorer GUI Delete on only target.txt, close Explorer and finalize with contemporaneous UI observations. If negative, at most one isolated Unicode-Path configuration; record exact native setting, no byte patching.
- [ ] Save screenshots/action logs if supported, commands, ZIP pairs, source manifests, detailed header table and tracker results. Any negative/unsupported result remains visible. No manipulation of tracker or headers to force Case2.
- [ ] Run full pytest, mypy src + new Python modules, changed Black/Flake8, pipcheck and diff checks. Request independent whole-branch review; fix verified important findings with RED/GREEN, recheck suite.
- [ ] Bundle run evidence with per-file SHA/size and overall checksum outside Git. Publish an evidence prerelease using established GitHub handoff, excluding downloaded tool binaries. Record limits and whether DoD met.
- [ ] Commit/push feature branch and create PR related to #19, not auto-close. No merge or issue closure requested in this task.

## Execution choice

User explicitly approved implementation of the reviewed design. Execute inline with one final independent review; do not add another permission gate for routine plan details. GUI actions follow existing session authorization and target only generated disposable working copies.
