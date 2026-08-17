# Architecture

## Overview
Cargo workspace, two crates:

```
powerscanner/
├─ core/   # UI-agnostic engine (lib) — scan, crypto, signatures, sink
└─ gui/    # eframe/egui binary — depends on core
```

`core` must not depend on any GUI crate (`eframe`/`egui`/`winit`). This keeps a
future Windows service / CLI reuse path open.

## Core modules
- `error` — `PsError` (thiserror enum), `PsResult<T>`.
- `crypto/` — `machine_key` (Argon2id over MachineGuid+salt), `vault`
  (AES-256-GCM encrypt/decrypt), `signer` (HMAC-SHA256 sign/verify).
- `signatures/` — `hashdb` (SHA-256 blacklist), `rules` (yara-x compile/scan),
  `store` (encrypted signature bundle + first-run import).
- `scan/` — `targets` (presets), `walk` (enumerate files), `incremental`
  (skip-cache), `hasher` (streaming SHA-256), `engine` (parallel orchestration),
  `result` (types), `paths` (results/cache dirs).
- `sink/` — `ResultSink` trait, `jsonl` (HMAC-signed append-only JSONL).

## GUI
- `app.rs` — state model (`Phase`, `AppState`, `ScanMsg`, `StreamLine`),
  background scan thread, `mpsc` channel to UI.
- `ring.rs` — reusable `Painter`-based circular progress.
- `main.rs` — dashboard layout; switches bottom region between live stream
  (scanning) and result table (done).

## Detection layers
1. SHA-256 exact match — O(1) set lookup.
2. YARA (yara-x) — pattern match, capped in-memory read (16 MiB).
3. Fuzzy (ssdeep + TLSH) — Phase 2; `DetectionKind` enum is the seam.

## Extension seams
- `ResultSink` trait — Phase 1 JSONL; later SQLite + server sink, no rewrite.
- `DetectionKind` enum — add `Ssdeep`/`Tlsh` variants for Phase 2.

## Data flow
`preset → resolve roots → walk files → (per file, parallel) hash + YARA →
ScanResult → ResultSink (signed JSONL) + UI stream/table`.

## Reference
Full task-level design + code:
`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md`.
