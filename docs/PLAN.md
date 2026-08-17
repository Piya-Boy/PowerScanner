# Plan

## Canonical plan
The full, authoritative implementation plan (18 tasks, TDD, complete code per
step) lives at:

**`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md`**

This file is the PM-level summary and index. The task board in `tasks/` mirrors
the 18 tasks as TASK-001..TASK-018. Do not duplicate code here — read the plan.

## Phase 1 scope
Standalone Windows malware scanner (Rust, egui). On-demand scan of files with
SHA-256 blacklist + YARA. Encrypted signature bundle, tamper-evident results,
native dashboard GUI. Rule bundle already produced (`signatures/`).

## Task map (plan task → board id)

| Board | Plan task | Deliverable | Layer |
|-------|-----------|-------------|-------|
| TASK-001 | 1 | Workspace scaffold + `PsError` | core |
| TASK-002 | 2 | Machine-derived key (Argon2id) | crypto |
| TASK-003 | 3 | AES-256-GCM vault | crypto |
| TASK-004 | 4 | HMAC result signer | crypto |
| TASK-005 | 5 | Result types | core |
| TASK-006 | 6 | Streaming SHA-256 hasher | scan |
| TASK-007 | 7 | Hash blacklist DB | signatures |
| TASK-008 | 8 | yara-x rules compiler | signatures |
| TASK-009 | 9 | Scan presets (targets) | scan |
| TASK-010 | 10 | Incremental scan cache | scan |
| TASK-011 | 11 | ResultSink trait + JSONL sink | sink |
| TASK-012 | 12 | Directory walker | scan |
| TASK-013 | 13 | Parallel scan engine | scan |
| TASK-014 | 14 | egui dashboard (ring/stream/table) | gui |
| TASK-015 | 15 | Encrypted signature loading | signatures |
| TASK-016 | 16 | Signed results wired end-to-end | gui+core |
| TASK-017 | 17 | README + signature docs | docs |
| TASK-018 | 18 | Reproducible rule bundle pipeline | tooling |

## Dependency order
001 → 002 → 003 → 004 → 005 → 006 → 007 → 008 → 009 → 010 → 011 → 012 → 013 →
014 → 015 → 016 → 017. TASK-018 is independent (tooling) and can run any time
after 001. Crypto tasks (002-004) block 011/015/016. Core types (005) block
011/013/014.

## Execution model
Human Owner gives direction → Claude plans → task is written to `tasks/` → Codex
chooses the specialist agent + model → agent implements on a `feature/*` branch
→ Codex verifies → Claude reviews against Acceptance Criteria → Human Owner
approves or requests fixes.
