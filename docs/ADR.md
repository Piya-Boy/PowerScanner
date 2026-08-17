# Architecture Decision Records

## ADR-001: Rust + cargo workspace (core / gui split)
**Status:** accepted.
**Context:** Need fast, low-footprint Windows scanner; reference project was
C#/.NET. **Decision:** Rust, workspace with UI-agnostic `core` lib + `gui` bin.
**Consequence:** core reusable by a future service/CLI; GUI swappable.

## ADR-002: yara-x (pure Rust) over C libyara
**Status:** accepted.
**Decision:** Use `yara-x` crate. **Consequence:** no C build dependency; some
legacy rules using unimplemented modules (e.g. `androguard`) are dropped.

## ADR-003: egui/eframe for the GUI
**Status:** accepted.
**Decision:** Native immediate-mode GUI. **Consequence:** low RAM, no webview;
less visually rich than web but fits the low-spec goal. Circular progress ring
hand-drawn via `Painter`.

## ADR-004: Machine-derived keys, not hardcoded
**Status:** accepted.
**Decision:** Argon2id over `MachineGuid` + per-purpose salt; AES-256-GCM at
rest; HMAC-signed results. **Consequence:** no secret in source; rule extraction
resistance is cost-raising, not absolute; result tampering is detectable.

## ADR-005: Ship a merged multi-source rule bundle (GPL-2.0)
**Status:** accepted.
**Decision:** Bundle ReversingLabs (MIT) + Yara-Rules (GPL-2.0) + bartblaze
(MIT), FP-pruned. **Consequence:** bundle is GPL-2.0; NOTICE + licenses shipped;
MIT-only rebuild path documented for commercial use.

## ADR-006: ResultSink trait + DetectionKind enum as extension seams
**Status:** accepted.
**Decision:** Abstract result storage behind `ResultSink`; detection type behind
`DetectionKind`. **Consequence:** Phase 2 (ssdeep/TLSH) and Phase 3 (SQLite/
server) plug in without rewriting Phase 1.
