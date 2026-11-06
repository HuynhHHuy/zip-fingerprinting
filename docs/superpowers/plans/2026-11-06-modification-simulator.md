# PH4-PROV-002 implementation plan

**Goal:** Generate labelled before/after ZIP pairs with installed archivers and
check real modification effects against the existing provenance tracker.

**Spec:** `docs/project/implementation-plan.md`, PH4-PROV-002.

**Architecture:** One stdlib-only Python runner calls native executables, validates
payload changes independently with `zipfile`, and records commands, versions,
SHA-256 and before/after tracker reports. A small PowerShell helper removes an
entry through the Windows compressed-folder shell handler. Each invocation owns
a fresh output directory; existing samples are never overwritten.

**Constraints and decisions:**
- Keep A (7-Zip → WinRAR Add), B (Bandizip → Windows shell removal), and C
  (WinZip → 7-Zip Modify). Missing tools are explicit skips, not substitutions.
- Windows shell removal uses MoveHere to a disposable directory with silent flags;
  this exercises removal by the shell handler, not the Explorer Delete UI.
- Add labelled 7-Zip/WinRAR control variants for this machine: timestamp-disabled
  Add, Modify, and shell removal. Never claim a variant is an exact paper replay.
- Record observations separately from expected cases and tracker predictions.
  Lack of Case 2 on newer software is a measured limitation, not a passing DoD.
- No installations, new dependencies, profile changes, pushes, or edits to user files.

## Steps

- [x] Write failing tests for missing-tool skips, modification validation, sample
  integrity, Case 1 control, retained baselines and non-overwriting runs.
- [x] Implement tool discovery/overrides, subprocess timeouts and native scenarios
  in `scripts/simulate_modifications.py`; add shell removal helper.
- [x] Run the tests and real installed-tool scenarios, inspect manifests and ZIPs.
- [x] Run full pytest and relevant static checks. Update README/backlog with the
  measured status, missing tools and exact reproduction command.

## Review focus

Missing executables must not be reported as successes; failed native commands
must remain visible; modification must affect exactly the intended payload;
baselines must remain unchanged; case coverage must come from actual reports,
not scenario labels. Review those paths before completion.

## Evidence / rulings

- Baseline: `python -m pytest`: 92 passed.
- Installed: 7-Zip 26.04, WinRAR 6.23.0; Bandizip/WinZip CLI unavailable.
- Default ASCII 7-Zip → WinRAR Add has overlapping profiles. Timestamp-disabled
  7-Zip baseline → WinRAR Add produces Case 1. Shell removal of a WinRAR ZIP
  preserves NTFS extra fields on this host; no Case 2 was observed in the probe.
- Execute in the current feature checkout and preserve the two pre-existing
  untracked presentation files. The user requested execution of the existing task.
- New tests observed failing against the placeholder; shell regression reproduced
  the disabled-script execution policy before the process-scoped fix.
- Final native run: `run-0fjyoqhr`, 4 generated, B/C skipped, Case1 true, Case2
  false. `--require-cases` returned 2 as intended. Acceptance remains pending.
- Independent review found no important correctness/data-safety/labeling issues.
  Full pytest after implementation: 99 passed (92 existing + 7 new).
