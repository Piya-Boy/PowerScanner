# Security Report

## 2026-08-17 — Threat model baseline
- Threat model + crypto design recorded in `docs/SECURITY.md`.
- Tamper-evident results (HMAC) = 100% detectable. Rule extraction resistance =
  raised cost, not absolute (honest limitation documented).
- Hard rules set for review: authenticated crypto on all persisted files, no
  hardcoded keys, no string-concat queries, no `unwrap` in lib paths.
- Reference project (SoSecure) defects catalogued to avoid: SQLi, hardcoded
  keys, `|| 1==1` bypass.

_Per-task security review pending as tasks complete._
