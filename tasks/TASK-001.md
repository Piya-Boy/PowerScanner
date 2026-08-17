# TASK-001

## Title
Workspace scaffold + PsError type

## Objective
Create the cargo workspace (root + `core` crate) and the shared error type so all
later tasks compile against a stable foundation.

## Context
First task of Phase 1. No code exists yet. Full spec + exact code in the plan:
`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md` → Task 1.

## Requirements
- Root `Cargo.toml` workspace (members `core`, `gui`) with pinned
  `[workspace.dependencies]` from the plan's Global Constraints.
- `core/Cargo.toml` consuming workspace deps.
- `core/src/error.rs`: `PsError` (thiserror enum: Io, Crypto, Signature, Yara,
  Config, Tamper) + `PsResult<T>`.
- `core/src/lib.rs`: `pub mod error;` + re-exports.

## Files To Modify
- Create: `Cargo.toml`, `core/Cargo.toml`, `core/src/lib.rs`, `core/src/error.rs`

## Dependencies
None.

## Acceptance Criteria
- [ ] `cargo test -p powerscanner-core error::` passes (2 tests: display format,
      io conversion).
- [ ] Workspace compiles clean.
- [ ] `PsError` derives Error+Display via thiserror; `#[from] std::io::Error`.
- [ ] Edition 2021, MSRV 1.74, deps pinned per Global Constraints.

## Constraints
- No `unwrap`/`expect` outside tests.
- Follow the plan's code exactly (TDD steps 1-6).

## Verification
Run the two inline tests; confirm they pass and the crate builds.

## Owner
Engineering (subagent)

## Status
READY
