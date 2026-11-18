# Case 2 GUI creation Implementation Plan

> Execute inline with superpowers:executing-plans and one final independent review.

**Goal:** One Bandizip 7.47 GUI creation -> Explorer Delete configuration on the current host; preserve negative findings and prepare VM instructions only if negative/inconclusive.
**Architecture:** Add GUI prepare/seal states to the existing focused workflow, reuse bounded evidence and deletion validation, preserve CLI compatibility.
**Tech:** Python stdlib, existing parser/tracker, pytest, native portable Bandizip and Explorer.
**Spec:** User-approved proposed plan in conversation, 18/11/2026; prior constraints in docs/superpowers/specs/2026-11-17-native-case2-design.md continue except explicitly expanded GUI creation.

## Constraints and acceptance

- One GUI ZIP/Normal configuration: UTF8 filename off, Unicode Path on, NTFS timestamps on, four existing source files without root prefix. One same-configuration retry only for operational failure.
- Private portable/profile and fresh runs; preserve prior artifacts, source anchors and immutable sealed baseline. No host associations/code-page/timezone/security changes, synthetic header edits or classifier tuning.
- Native Case2 requires all survivor structural changes, intact payloads, GUI creation+Delete observations and independent tracker comparison; offset/timestamp-only does not qualify.
- On negative/inconclusive result prepare VMware Windows10v2004 EN x64 instructions,2vCPU/4GiB/64GiB thin,snapshot clean. No ISO available: no guest creation/installation or historical execution. Never install old Bandizip on host.
- Preserve CLI defaults and legacy runs. Exit2 pending creation/deletion,1 failure; finalize existing exit semantics.
- Commit/push feature branch, publish new evidence prerelease, PR related to#19. No merge/issue closure.

## Task1: GUI baseline lifecycle

- [x] Tests RED: prepare creation_mode=gui yields awaiting_creation and no ZIP/process, seal validates actual inventory/CRC/payload/source anchors and GUI log/run/tool/path/time/selection observations, repeat seal refusal, missing/bad ZIP and logs persisted, deletion finalize requires creation evidence, CLI legacy compatible.
- [x] Implement prepare --creation-mode cli|gui (default cli), seal-creation RUN --gui-log PATH. Source/log anchors established before GUI; sealing records immutable before hash and creates after.zip, moves awaiting_gui. GUI creation operator-only cannot establish native Case2. No overwrite after.zip or sealed baseline.
- [x] GREEN, full suite and static checks, commit.

## Task2: Native observation and conditional VM handoff

- [x] Copy verified portable to private profile, generate GUI source, observe exact ZIP/Normal settings and selection, create before.zip via actual Bandizip GUI, close and seal. Delete only target.txt through Explorer, close and finalize. Preserve UI observations and actual raw headers/encoding, never claim CP949 from UI.
- [x] Fresh native control-add Case1 pair. Negative/partial/failure stays visible. If negative/inconclusive, document Windows10v2004 media gate and isolated guest protocol only, with official Bandizip6.29 warning; no guest execution before valid media.
- [x] Update simulator instructions/backlog/reproduction report. Package new artifacts separately with inventory and SHA; preserve prior release. No proprietary binaries in package.

## Task3: Verification and delivery

- [x] pytest all; mypy src+changed experiment; changed Black/Flake8;pipcheck;diff. One fresh-context whole-branch review, important fixes RED/GREEN and full suite.
- [x] Publish evidence prerelease, public download checksum verification, push and create follow-up PR; monitor Windows/Ubuntu Python3.10/3.11 CI, with final status reported in PR/handoff. Keep#19 open unless later explicitly closed after actual DoD.

## Review focus

1. GUI-created baseline falsely labelled native when only operator assertion exists.
2. Creation evidence mismatched source/selected names/tool/output/run/time or modified after sealing.
3. CLI legacy behavior and new state/exit-code regression.
4. Reparse/path escapes, unbounded reads and frozen-baseline overwrite.
5. Scientific claims exceed actual header/payload/GUI observations or VM media remains missing.

## Execution and review result

PR#28 open; GUI run run-case2-hz8kgcll finalized_negative/scope none, newCase1 run-16gz65r7 positive; no retries. Missing valid Windows10v2004 media: VM runbook only, no guest created/installed/executed. Local364passed/3existing symlink skips; mypy16/Black2/Flake8/pipcheck/diff clean. Independent review: no Critical/Important/Minor findings;33bundle members and raw comparison independently verified. Public evidence prerelease downloaded and SHA/size matched. CI final status is tracked on PR#28 rather than committed into its own triggering SHA. ScientificDoD remains false, #19 open.

Review rulings: historical guest behavior unjudged because media absent (cost: Case2 unmet); public delivery verified and CI is monitored at handoff; GUI records remain operator observations (cost: no cryptographic authorship proof). Filesystem operations assume closed apps/no concurrent writer and a trusted private portable profile; transactional replacement protection and inherited after.read_bytes/config-INI reparse races are not hardened in this change (cost: hostile concurrent/profile inputs unsupported). No deferred Minor findings.
