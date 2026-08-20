# Review

| Task | Title | Status | Implementation | Verification |
|------|-------|--------|----------------|--------------|
| TASK-002 | Machine-derived key (Argon2id) | PASS | `core/src/crypto/` | Targeted 8/8; workspace 8/8; Clippy clean; re-review clean |
| TASK-003 | AES-256-GCM vault | PASS | `core/src/crypto/vault.rs` | Targeted 3/3; workspace 11/11; Clippy clean; re-review clean |
| TASK-004 | HMAC-SHA256 result signer | PASS | `core/src/crypto/signer.rs` | Targeted 3/3; workspace 14/14; Clippy clean; re-review clean |
| TASK-005 | Result types | PASS | `core/src/scan/result.rs` | Targeted 2/2; workspace 16/16; Clippy clean; re-review clean |
| TASK-006 | Streaming SHA-256 hasher | PASS | `core/src/scan/hasher.rs` | Targeted 1/1; workspace 17/17; Clippy clean; re-review clean |
| TASK-007 | Hash blacklist DB | PASS | `core/src/signatures/hashdb.rs` | Targeted 2/2; workspace 19/19; Clippy clean; re-review clean |
| TASK-008 | yara-x rules compiler | PASS | `core/src/signatures/rules.rs` | Targeted 3/3; workspace 22/22; Clippy clean; re-review clean |
| TASK-009 | Scan presets (targets) | PASS | `core/src/scan/targets.rs` | Targeted 3/3; workspace 25/25; Clippy clean; Startup roots covered; re-review clean |
| TASK-010 | Incremental scan cache | PASS | `core/src/scan/incremental.rs` | Targeted 2/2; workspace 27/27; Clippy clean; JSON error mapping clean; re-review clean |
| TASK-011 | ResultSink + JSONL sink | PASS | `core/src/sink/` | Targeted 4/4; workspace 31/31; Clippy clean; raw HMAC-before-parse; re-review clean |
| TASK-012 | Directory walker | PASS | `core/src/scan/walk.rs` | Targeted 3/3; workspace 34/34; Clippy clean; symlink/reparse scope guards; re-review clean |
| TASK-013 | Parallel scan engine | PASS | `core/src/scan/engine.rs` | Targeted 5/5; workspace 39/39; Clippy clean; hash-preserving fallback; serialized workload progress; re-review clean |
| TASK-014 | egui dashboard | PASS | `gui/src/`, `core/src/signatures/rules.rs` | GUI 8/8; core 40/40; workspace 48/48; build, fmt, Clippy clean; bounded worker, live progress, cumulative malicious metric, strict rule-source guard; two independent re-reviews clean |
| TASK-015 | Encrypted signature loading (portable key) | PASS | `core/src/signatures/store.rs`, `gui/src/app.rs` | Store 6/6; workspace 54/54; build, fmt, Clippy clean; strict import, portable AES-GCM bundle, atomic publish, permission-error propagation; two independent re-reviews clean |
| TASK-016 | Signed results wired end-to-end | PASS | `core/src/scan/paths.rs`, `core/src/sink/jsonl.rs`, `gui/src/app.rs` | Core 49/49; GUI 8/8; workspace 57/57; build, fmt, Clippy, metadata locked clean; HMAC result persistence, ACL/DACL policy, cross-process append/verify locks; two independent re-reviews clean |
| TASK-017 | README + signature format docs | PASS | `README.md`, `docs/SIGNATURES.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md` | API/path/security consistency reviewed; build/staging, presets, import/re-import, portable bundle, signed results and Phase 1 limitations documented; two independent re-reviews clean |
| TASK-018 | Reproducible YARA rule bundle pipeline | PASS | `tools/build-rules.sh`, `tools/rule-sources.txt`, `.gitattributes`, `signatures/.bundle-date` | Git-pinned multi-source fetch, compile/dedupe/FP filtering, collision guard, manifest hashes, LF-stable artifacts, atomic publish rollback, self-test and bash syntax checks; two independent re-reviews clean |
| TASK-019 | Build-time bundle sealing (Defender-safe ship) | PASS | `tools/seal-bundle/`, `tools/package-release.ps1`, `signatures/bundle.psenc` | Sealer validates hashes/rules, portable AES-GCM, SHA-bound manifest, Windows atomic replace, clean-checkout verify mode, safe release-root confinement, mandatory attribution/licenses, plaintext leak guard; workspace 49 core + 8 GUI + 2 tool tests, Clippy/fmt clean; two independent re-reviews clean |
| FIX-001 | Scan error must not read as Clean | PASS | `core/src/scan/result.rs`, `core/src/scan/engine.rs`, `gui/src/app.rs`, `gui/src/main.rs` | Per-file failures preserve error text as `Verdict::Error`; GUI counts/displays/filters errors separately; workspace 50 core + 9 GUI + 2 tool tests, Clippy/fmt clean; two independent re-reviews clean |

## TASK-002 Review Findings (Resolved)

- The security guarantee was reduced to offline/manual tamper evidence; the
  README, SECURITY.md, and ARCHITECTURE.md now state that active local forgery
  is out of scope.
- GUID + volume-serial composition and Windows path-root behavior are covered
  by direct tests. Independent re-review found no remaining issues.

## Independent PM Review — full Phase 1 (2026-08-21)

PM (Claude) re-verified the whole workspace independently of the loop's
self-reported state: `cargo build --workspace`, `cargo test --workspace`
(57 core+GUI, 2 tool tests, 0 failed), `cargo clippy --workspace --all-targets`
(0 warnings). Read crypto, engine, sink, and store in full. Overall quality is
high — several parts exceed the plan (BCryptGenRandom CSPRNG, volume-serial
binding, cross-process file locks, atomic seal). Three findings:

| # | Sev | Location | Finding | Disposition |
|---|-----|----------|---------|-------------|
| F1 | HIGH | `core/src/scan/engine.rs:105` | A per-file scan error (unreadable/locked file) was swallowed by `unwrap_or_else` into `Verdict::Clean`. Contradicted ARCHITECTURE ("absence of detection is never reported as clean") and created an evasion gap. | **Resolved by FIX-001**; independent re-review clean |
| F2 | LOW | `core/src/signatures/store.rs:17` | `embedded_secret()` XOR-split is obfuscation, not security. Consistent with ADR-004 (cost-raising, not absolute) but should be commented as such so no one mistakes it for protection. | comment-only, optional |
| F3 | LOW | `core/src/crypto/signer.rs:37` | `unreachable!()` sits in a library path (technically the "no panic in lib" rule). The HMAC "any key length" invariant is genuinely total, so it cannot fire; acceptable with its comment. | accepted |

Note: the per-task PASS rows below were authored by the engineering loop (Codex
self-review). F1 was missed by the original test set and is now covered by
explicit unreadable-file and GUI error-visibility regressions.

---

A task lands here after Engineering reports done. PM reviews against Acceptance
Criteria → PASS (move to DONE.md) or NEEDS_FIX (write report, return to
Engineering).
