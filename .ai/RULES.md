# Rules

Operating rules for all agents on the PowerScanner project.

## Workflow

`PLAN → DELEGATE → EXECUTE → REVIEW → FIX → VERIFY → DOCUMENT → CONTINUE`

Never skip REVIEW or VERIFY. A task is never marked DONE without passing review.

## Source of truth (priority order)

```
docs/PRD.md → docs/ARCHITECTURE.md → docs/SECURITY.md → docs/PLAN.md
→ docs/ROADMAP.md → tasks/ → code
```

The canonical implementation plan is
`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md` (18 tasks, TDD, full
code). The task board (`tasks/`) mirrors it; `docs/PLAN.md` links to it. On
conflict: stop, analyze, do not guess, escalate to CEO if the decision is
significant.

## Must

- Read context (this file, STATE.md, MEMORY.md, the plan) before working.
- Follow the task's Acceptance Criteria exactly.
- Write tests first (TDD) per the plan.
- Update `.ai/STATE.md` after every significant action.
- Update `.ai/MEMORY.md` when a durable lesson/decision appears.
- Leave the repo in a state the next agent can continue from.
- Use Conventional Commits. Atomic commits.

## Must not

- Guess requirements.
- Skip Acceptance Criteria or Security Review.
- Change architecture unilaterally (escalate to CEO).
- Commit secrets or generated build artifacts (except the shipped rule bundle).
- Mark a task DONE without verification.
- Work directly on `main`/`master`/`develop` — use `feature/*`, `bugfix/*`,
  `refactor/*`, `chore/*`, `docs/*`.

## Escalate to CEO before

Major architecture change · production release · destructive data operation ·
major scope change · security exception · anything hard to reverse.

## Project-specific hard constraints (from the plan)

- Rust edition 2021, MSRV 1.74+, Windows x64 target.
- `core/` crate must not depend on any GUI crate.
- Authenticated encryption or signatures on all persisted files; no plaintext
  secrets; no hardcoded keys (machine-derived at runtime).
- No string concatenation into queries/commands.
- No `unwrap()`/`expect()` in library paths except tests.
