# Roadmap

## Phase 1 — Standalone MVP (current)
Rust + egui, on-demand scan, SHA-256 + YARA, encrypted signatures, tamper-evident
results, dashboard GUI. 18 tasks — see `docs/PLAN.md`.
Status: planning complete, implementation not started.

## Phase 2 — Depth
- Fuzzy hashing: ssdeep (`ffuzzy`) + TLSH (`tlsh-fixed`) as detection layer 3,
  run only on still-clean executable files (perf guard). `DetectionKind` seam
  already in place.
- Process + memory scanning (OpenProcess/ReadProcessMemory, admin).
- Autorun / registry / startup inspection.

## Phase 3 — Operations
- Real-time watch (ReadDirectoryChangesW).
- Scheduled scans.
- SQLite result storage (`ResultSink` seam) + backend/server sync
  (agent+server model, like the SoSecure reference).

## Phase 4 — Advanced
- Behavior/heuristic detection (ETW).
- Binary hardening / obfuscation.

## Notes
Phase boundaries are set so Phase 1 interfaces (`ResultSink`, `DetectionKind`)
absorb later phases without a rewrite.
