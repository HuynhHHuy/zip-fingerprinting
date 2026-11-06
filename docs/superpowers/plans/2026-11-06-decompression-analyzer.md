# PH5-DEC-001 implementation plan

**Goal:** Look up decompressor candidates using Table 8 and flag two timestamp
reversal conditions without inspecting or extracting files.

**Spec:** `docs/project/implementation-plan.md`, PH5-DEC-001; local paper,
Section 4.3 (page 7) and Table 8 (page 9), text and rendered image inspected.

**Architecture:** A private 13-row lookup table in `decompression.py`, one lookup
method, the existing compatibility wrapper, and a datetime comparison method.
Python stdlib only; CLI integration and filesystem measurement remain PH7/PH5-DEC-002.

## Decisions

- The PDF has 13 rows (4 file + 1 no-header folder + 4 populated folder + 4 empty
  folder), not the 15 stated in the backlog. Correct the backlog and missing row
  in the research guide instead of inventing data.
- Entry types: `file`, `folder_with_files`, `empty_folder`, `folder_no_header`.
  Also accept literal table state labels in the legacy `evaluate_bmac_pattern` API.
- Accept R/H/E patterns with whitespace/case normalization. Malformed input raises
  ValueError; valid unlisted patterns or header IDs return no candidates.
- Extra fields: None/`None`, integer IDs, hexadecimal strings. `N/A` only applies
  to no-header folders. Preserve every matching candidate in table column order.
- `check_time_reversal` accepts optional datetimes. Compare each available pair;
  return `CREATION_AFTER_MODIFICATION` and/or `SUBFOLDER_BEFORE_PARENT`. Missing
  pairs are unassessed. Reject mixed naive/aware datetimes within a pair; compare
  aware timestamps as UTC instants. These are observations, not proof of tampering.

## Steps

- [x] Add independently transcribed Table 8 benchmark rows and input/reversal tests.
- [x] Observe failure against the stub, implement lookup and comparisons, rerun tests.
- [x] Update README/backlog/research guide and evaluation report with exact scope.
- [x] Run full pytest, mypy, formatting/lint checks; request independent review.

## Review focus

All tied candidates must survive; no-header folders differ from header/no-extra
folders; unknown header IDs must not fall back to None; equal timestamps must not
flag reversal; timezone offsets must not reverse comparison results.

## Evidence

- Starting checkout: `feat/automated-classifier`, a646831; two unrelated untracked
  presentation files preserved. Implement in the current feature checkout.
- Table 8 rendered using pypdfium2 installed only in the existing .venv-ci tooling
  environment, without adding a project dependency.
- RED: 34 new tests failed against the stub; four existing matrix tests passed.
- GREEN: full suite 133 passed; mypy src clean; Black and Flake8 changed files
  clean; git diff --check clean. API demonstration confirms unique/tied/all-tool
  candidate results and the creation-after-modification warning.
