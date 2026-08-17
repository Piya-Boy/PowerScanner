# PowerScanner — Product Requirements

## Problem
Windows servers/hosts need a fast, low-footprint malware scanner that runs
standalone, detects known-bad files, and produces tamper-evident results.

## Users
Operators of Windows machines (server + workstation) who want on-demand malware
scanning without a heavyweight agent.

## Goals
- Fast scan, low CPU/RAM (runs on low-spec hardware).
- Detect malware in files via SHA-256 blacklist + YARA rules.
- Native desktop GUI (no CLI dependency for the user).
- Encrypt the signature database and config at rest.
- Make scan results tamper-evident (malware on the box cannot forge/alter them).

## Non-goals (Phase 1)
Backend/server sync, SQLite storage, process/memory/registry scanning,
behavior/heuristic detection, real-time watch, scheduled scans, fuzzy hashing,
binary obfuscation. (Several are scheduled for later phases — see ROADMAP.)

## Functional requirements
1. Three scan presets: Quick, Full (all drives), Risky Spots (Temp, AppData,
   Downloads, Startup, System32, Windows\Temp).
2. Detection: SHA-256 hash blacklist + YARA (yara-x engine).
3. Incremental scan: skip files whose size+mtime are unchanged since last scan.
4. Import own signatures (`hashes.txt` + `rules/*.yar`); sealed encrypted at rest
   after first run.
5. GUI dashboard: circular progress ring with live %, three scan buttons, metric
   tiles (Scanned/Malicious/Elapsed), a live file stream during scanning that
   switches to a filterable result table when the scan finishes.
6. Results view is read-only in Phase 1 (view/report; no delete/quarantine).
7. Persist signed, append-only results to an ACL-protected directory.

## Non-functional requirements
- Rust, Windows x64, edition 2021, MSRV 1.74+.
- Multi-threaded scanning (rayon).
- Authenticated encryption/signatures on all persisted files; no hardcoded keys.
- Startup with the full bundled ruleset must stay fast (measured: ~0.5s to load
  13,134 compiled rules).

## Acceptance (Phase 1 overall)
- Clicking a preset scans, animates the ring, streams files, then shows a
  filterable result table.
- EICAR-like test file is detected; clean files (incl. ones containing URLs/IPs)
  are not falsely flagged.
- Signature bundle loads encrypted; results file is HMAC-verifiable and tamper
  is detectable.
