# PH6-DATA-002 implementation and verification ledger

User-approved spec: Windows CLI ground-truth pipeline from the preceding plan.
Execute inline with TDD and one independent review. Implementation initially stayed
uncommitted; the subsequent user instruction authorizes documentation of acceptance
limits, then commit and push on a dedicated task branch.

## Contract

- Four adapters: 7zip, winrar, bandizip, powershell. PowerShell is never Explorer.
- Three variants: root (set1 prefix), contents (no set1 prefix), auxiliary (auxiliary prefix).
- One fresh source per sample, verify against PH6-DATA-001 baseline and regenerate
  immediately before launching the native process to restore atime/mtime.
- Immutable run directories; schema-v1 append-only catalogue under data-dir.
- Payload/CRC/name validation independent of classifier; ground truth is invocation provenance.
- Native DoD: 9 verified ZIPs from installed 7-Zip/WinRAR/PowerShell, plus explicit Bandizip skips.
- Windows only; no GUI equivalence, no creation/change-time guarantees, no BMAC/accuracy claims.

## Implementation steps

- [x] Write tests for archive validation, name encodings, output/catalogue preservation,
  missing/failed/timeout tools, CLI and three real native adapters. Observe RED.
- [x] Implement generator and PowerShell adapter using existing simulator helpers.
- [x] Run focused tests; inspect genuine archive differences without repairing headers.
- [x] Generate default dataset; verify 9 generated, 3 skipped and no failed samples.
- [x] Update documentation/backlog/report, run full tests/static checks and fresh review.

## Interfaces and decisions

- `generate(data_dir, tools, selected_tools=None, variants=None) -> dict` returns the
  saved run report; `discover_tools() -> dict` and `exit_code(report) -> int` support CLI/tests.
- `validate_archive(path, expected, directories, legacy_encoding) -> dict` accepts
  expected file bytes and directory names and returns observed files/directories.
- CLI: `--data-dir`, repeated `--tool`/`--variant`, executable overrides per adapter.
- Catalogue: `{schema_version: 1, runs: [...]}`; `{}` alone is the initial state.
  Unknown schema is refused before generating. Both run report and catalogue use atomic JSON writes.
- Reuse sibling simulator helpers directly; no shared-module extraction.
- Start: HEAD 3209c53; only unrelated untracked PPTX present. Keep current checkout.

## Evidence and rulings

- RED: 19 tests failed against placeholder (missing interfaces and CLI false success).
- GREEN: 19 tests passed, including real Windows 7-Zip/WinRAR/PowerShell runs.
- Ruling: only local annotations were added to reused simulator code for mypy;
  timeout stdout/stderr retention is the sole functional simulator change.
- Independent review found missing `zlib.error` handling. A real invalid DEFLATE
  stream in a unit fault-injection test reproduced RED; catch zlib.error/EOFError
  in the sample handler made it GREEN. Reviewer independently confirmed resolution.
- Ruling: Python child processes resolve Archive 1.2.7, while host-shell probing
  resolved 1.0.1.0. Record engine/module path and explicitly import the measured
  module in compression commands; do not label samples using the host-shell version.
- Final focused tests: 20 passed. Full suite: `python -B -m pytest -p no:cacheprovider`
  yielded 161 passed, no skips, Windows/Python 3.11.9 (9.50 seconds).
- Mypy `src scripts/generate_ground_truth.py`: clean, 16 source files; Black/Flake8
  three changed Python files, pip check and diff whitespace checks passed.
- Default runs run-xzp9n65j and run-49gonnjf each produced 9 generated, 3 skipped,
  0 failed. Last run includes explicit PowerShell module pinning. Catalogue retains
  both reports; latest saved report equals catalogue entry and 9 ZIP hashes match.
- Native tools: 7-Zip 26.04, WinRAR 6.23.0; Windows PowerShell 5.1.26100.9818,
  Archive 1.2.7. Bandizip absent. PowerShell missing directory headers are observations,
  not repaired. GUI/macOS/Linux/BMAC/accuracy remain unverified.
