# Codex Handoff — TASK-001

You are the Engineering team. Implement TASK-001 exactly per the plan. Do not
change architecture or requirements. Work on branch `feature/core-scaffold`.

## Read first
- `docs/superpowers/plans/2026-08-17-powerscanner-phase1.md` → **Task 1** (has the
  exact code for every file).
- `.ai/RULES.md` (hard constraints), `docs/ARCHITECTURE.md`.

## Objective
Create the cargo workspace (root + `core` crate) and the shared `PsError` type.

## Files to create
- `Cargo.toml` (workspace root — members `core`, `gui`; pinned
  `[workspace.dependencies]` exactly as in the plan's Global Constraints)
- `core/Cargo.toml`
- `core/src/lib.rs`
- `core/src/error.rs`

Use the code from Task 1 Steps 1–4 verbatim.

## Acceptance criteria (must all pass)
- [ ] `cargo test -p powerscanner-core error::` → 2 tests pass
- [ ] `cargo build` clean
- [ ] `PsError` is a `thiserror` enum with variants Io(`#[from]`), Crypto,
      Signature, Yara, Config, Tamper; plus `pub type PsResult<T>`
- [ ] edition 2021, MSRV 1.88, deps pinned per Global Constraints
- [ ] no `unwrap`/`expect` outside tests

## Constraints
- Do NOT create the `gui` crate yet (that is TASK-014). The workspace `members`
  list includes `gui`, so either create a minimal placeholder `gui` that builds,
  OR temporarily list only `core` in members and note it — prefer the latter to
  keep TASK-001 self-contained; TASK-014 re-adds `gui`.
- Conventional Commits. No `Co-Authored-By` trailer. Author = git user.

## Report back (paste to Claude PM)
```
# Agent Result
## Task: TASK-001
## Agent: Backend / Codex
## Model: 5.6 Terra
## Status: PASS / NEEDS_REVIEW / BLOCKED
## Changes: <files created>
## Tests: <cargo test output summary>
## Issues: <any>
## Next Action: <ready for review>
```

## Git
```bash
git checkout -b feature/core-scaffold
# ... implement ...
git add Cargo.toml core/
git commit -m "feat: workspace scaffold and PsError type"
```
