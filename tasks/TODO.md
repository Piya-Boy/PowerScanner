# TODO

All 18 tasks are specified in full (code + tests + acceptance) in
`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md`. This board tracks
status only. Pick tasks in dependency order (see `docs/PLAN.md`).

| Task | Title | Owner | Status | Depends on |
|------|-------|-------|--------|------------|
| TASK-001 | Workspace scaffold + PsError | Engineering | READY | — |
| TASK-002 | Machine-derived key (Argon2id) | Engineering | BLOCKED | 001 |
| TASK-003 | AES-256-GCM vault | Engineering | BLOCKED | 002 |
| TASK-004 | HMAC result signer | Engineering | BLOCKED | 002 |
| TASK-005 | Result types | Engineering | BLOCKED | 001 |
| TASK-006 | Streaming SHA-256 hasher | Engineering | BLOCKED | 001 |
| TASK-007 | Hash blacklist DB | Engineering | BLOCKED | 001 |
| TASK-008 | yara-x rules compiler | Engineering | BLOCKED | 001 |
| TASK-009 | Scan presets (targets) | Engineering | BLOCKED | 001 |
| TASK-010 | Incremental scan cache | Engineering | BLOCKED | 001 |
| TASK-011 | ResultSink + JSONL sink | Engineering | BLOCKED | 004,005 |
| TASK-012 | Directory walker | Engineering | BLOCKED | 001 |
| TASK-013 | Parallel scan engine | Engineering | BLOCKED | 005,006,007,008,010,012 |
| TASK-014 | egui dashboard | Engineering | BLOCKED | 005,009,013 |
| TASK-015 | Encrypted signature loading | Engineering | BLOCKED | 003,007,014 |
| TASK-016 | Signed results wired end-to-end | Engineering | BLOCKED | 004,011,014 |
| TASK-017 | README + signature docs | Tech Writer | BLOCKED | 016 |
| TASK-018 | Reproducible rule bundle pipeline | Engineering | READY | 001 |

Legend: READY = deps met, can start · BLOCKED = waiting on deps · see
IN_PROGRESS.md / REVIEW.md / DONE.md as tasks move.
