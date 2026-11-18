# PH4-PROV-002 / #19 — Native Explorer Delete experiment

## Intent and agreed approach

Complete the missing native Case 2 experiment: retain ZIPs before and after
deleting one member in real Windows Explorer, measure effects on untouched
entries independently, then compare those observations with ProvenanceTracker.
User selected Bandizip 7.x portable and the current Windows environment first.
Historical Bandizip 6.29 / Windows VM is deferred unless current results warrant
another experiment. Ubuntu/Wine is not labelled native Explorer evidence.

Existing simulator creates Case 1 controls and shell MoveHere removal samples;
MoveHere is not Explorer Delete. Preserve that distinction and existing APIs
because the ground-truth generator and BMAC tracer reuse simulator helpers.

## Alternatives considered

- Selected: current Bandizip portable + actual Explorer GUI deletion. Smallest
  environment change, supports real local evidence; cannot promise 2021 behavior.
- Deferred: historical Bandizip 6.29 in an isolated Windows VM. Closer to the paper,
  but needs a Windows guest and old software with a vendor security warning.
- Rejected as proof of Case 2: shell MoveHere alone or synthetic header edits.
  Existing MoveHere remains a separately labelled control, not a substitution.

## Constraints

- Branch from merged main containing PRs #25/#26; preserve all existing artifacts
  and the user's untracked presentation/plan. Use fresh run directories only.
- Download portable Bandizip from Bandisoft; record URL, download SHA-256,
  executable SHA-256/version and signing information. Do not commit binaries.
- Use an isolated portable profile if supported. Do not register associations,
  change system code page/timezone/security settings or upgrade installed tools.
  If a required setting cannot be isolated, report that before changing it.
- Only generated tiny source/ZIPs are operated on. Never open or delete members
  of a user-provided archive. Retain immutable before.zip and working after.zip.
- No fabricated headers, silent archiver substitution or classifier-derived truth.

## Experiment and implementation boundary

1. Inventory Windows/build, Explorer/zipfldr versions, code pages and actual
   archivers. Preserve the current Case 1 control from 7-Zip -> WinRAR Add.
2. Add a prepare/finalize workflow alongside the existing simulator. Prepare
   creates private source files (ASCII target/keep plus Unicode survivors), runs
   actual Bandizip, checks the baseline payload/inventory, records header evidence
   and copies the archive to after.zip. It then returns an awaiting-GUI record.
3. Open that after.zip explicitly in Explorer's compressed-folder view, select
   only target.txt and perform Delete. Record operator/action times, actual app/
   archive path, selection and observed confirmation/result; save scoped evidence
   where supported. The CLI itself does not pretend to perform GUI automation.
4. Finalize validates that only target.txt disappeared, all survivor payload hashes
   match, before.zip stayed byte-identical and the after ZIP has valid CRC and no
   duplicate/unsafe/ambiguous names. Record GUI action evidence distinctly from
   process command logs; an operator assertion is labelled as such, not proof
   obtained from archive bytes alone.
5. For each survivor, retain before/after LFH/CDH fields, raw extra bytes/IDs and
   concrete deltas. Distinguish offset/position changes caused by member removal
   from structural extra/flag/version changes. Resolve Unicode using UTF-8 flags,
   valid Unicode Path CRC and recorded Windows code page; reject ambiguous names.
6. Assess observed rewrite scope (all/partial/none), keep that separate from
   tracker Case 2 and suspected applications. Case 2 acceptance requires actual
   structural changes on all remaining entries, intact payloads, verified native
   operation evidence and tracker comparison. A tracker flag alone never passes.
7. Try default native Bandizip settings first. If needed, an additional labelled
   native Unicode-Path configuration may be tested in the private portable profile;
   record exact configuration. No system code-page changes or archive patching.

Implementation should reuse existing discovery/version/process/SHA helpers and
parser/extra decoders, adding only the focused workflow and detailed comparison.
Exact function/CLI names are left to the implementation plan. No tracker change
unless an independently reproduced bug is demonstrated by native observations.

## Builder decisions and bounded contracts

- Qualifying rewrite evidence: changes in extra-field IDs/order/layout/length,
  host/version fields, compression method, UTF-8/data-descriptor flags or raw
  filename encoding with the same verified decoded identity. Record all deltas,
  but offset/relocation/order, CRC/size and timestamp-value-only changes do not
  establish Case 2 alone. Structural changes must affect every surviving entry
  to meet this experiment's global Case 2 acceptance; partial changes are reported
  separately. Do not alter tracker rules merely to match this assessment.
- GUI evidence levels: contemporaneous UI observations tied to run ID, exact
  archive path, selected target and before/after state support native acceptance.
  Operator-only assertions remain explicitly unverified. Schema validation can
  reject incomplete/path-mismatched records, not prove that an assertion is true.
- State lifecycle: new unique prepared run -> awaiting GUI -> finalized positive,
  finalized negative or failed. Anchor source and baseline checksums before GUI;
  write records atomically. Only finalize an awaiting run owned by this workflow;
  refuse path escapes and symlink/reparse inputs. Repeated finalize must refuse
  mutation or return an existing frozen result. Preserve incomplete/failed states.
  Finish/close Explorer writes before capturing an immutable after snapshot;
  changing/unreadable archives remain pending/failed rather than a valid result.
- Match entry identities losslessly from raw names/flags and CRC-validated
  Unicode Path fields using recorded code-page evidence. Validate LFH/CDH identity
  agreement, distinguish valid encoding differences from malformed names, and
  reject collisions/ambiguity. Do not blindly match zipfile's CP437 names against
  parser or Windows names. Payload reads remain CRC-checked and memory-bounded.
- Acceptance needs one fresh native Case 1 pair plus one native global Case 2
  pair; regenerate Case 1 for this handoff rather than depend on old local paths.
  Run one default Bandizip configuration and, only if needed, at most one isolated
  Unicode-Path configuration. Record negative outcomes for each. No unbounded
  search across tools/versions or automatic escalation to a historical VM.

## Evidence and acceptance

Keep per-run machine-readable report and a readable per-entry header table,
before/after ZIPs, source/payload manifest, commands, tool/configuration evidence,
GUI action log and tracker outputs. Persist intermediate/failed/negative results.
Package evidence outside Git with SHA-256; use the repository's established
GitHub evidence prerelease approach at handoff, retaining original runs.

DoD: native evidence covers Case 1 and Case 2 in at least two valid pairs; actual
Case 2 changes untouched headers while their payloads remain intact; report and
artifacts can be independently verified and the workflow can be rerun.
Negative Case 2 findings are valuable results but keep #19 open and DoD false.
Do not claim full historical reproduction, accuracy or exact GUI/CLI equivalence.

## Verification and delivery

TDD for new pure comparison and prepare/finalize state/error contracts, including
unchanged archive, payload corruption, wrong deletion, incomplete/path-mismatched GUI
record, name ambiguity and offset-only changes. Synthetic fixtures test logic;
real archivers/Explorer produce native acceptance evidence.
Run relevant tests, full pytest, mypy, changed-file Black/Flake8, pip check and
diff checks. Obtain independent review. Commit/push and prepare a PR for #19
with measured outcomes and explicit limits; do not auto-close on code alone.
