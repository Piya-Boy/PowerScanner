# PowerScanner

PowerScanner is a planned standalone Windows malware scanner written in Rust
with a native egui desktop dashboard, SHA-256 blacklist detection, YARA-X rule
matching, encrypted signatures, and tamper-evident scan results.

> Current status: Phase 1 planning is complete. The Rust workspace is not
> implemented yet, so build and run commands below become active after
> `TASK-001` creates the Cargo workspace and the remaining Phase 1 tasks land.

## Phase 1 scope

Phase 1 targets an on-demand Windows x64 scanner with:

- Native desktop GUI built with `eframe`/`egui`.
- Three scan presets: Quick, Full, and Risky Spots.
- SHA-256 exact-match blacklist checks.
- YARA-X rule compilation and scanning.
- Incremental scan cache using file size and modification time.
- First-run signature import from `signatures/`, then encrypted at rest.
- HMAC-signed append-only JSONL results under `%ProgramData%\PowerScanner`.

Phase 1 does not include real-time monitoring, process or memory scanning,
registry inspection, quarantine/delete actions, server sync, SQLite storage,
fuzzy hashing, or behavior detection.

## Repository layout

```text
.
|-- .ai/          # Agent workflow state, rules, team, and model routing
|-- docs/         # Product, architecture, security, roadmap, and plan docs
|-- reports/      # Development, QA, release, and security reports
|-- signatures/   # Bundled hash and YARA signature assets
`-- tasks/        # Task board and Codex handoff prompts
```

The planned Rust workspace layout is:

```text
.
|-- core/         # UI-agnostic scan, crypto, signatures, and result sink logic
`-- gui/          # eframe/egui desktop app
```

`core` must not depend on GUI crates, so the scan engine can later be reused by
a CLI, Windows service, or backend-connected agent.

## Build

After the Cargo workspace exists:

```bash
cargo build --release
```

Run the full test suite:

```bash
cargo test
```

Task-specific checks are tracked in [`docs/PLAN.md`](docs/PLAN.md) and the
canonical task plan at
[`docs/superpowers/plans/2026-08-17-powerscanner-phase1.md`](docs/superpowers/plans/2026-08-17-powerscanner-phase1.md).

## Run

After building the GUI binary:

```bash
cargo run --release -p powerscanner-gui
```

The app loads signatures from a `signatures/` folder next to the executable. On
first run, plaintext signature sources are imported and sealed into an encrypted
bundle for later runs.

## Scan presets

| Preset | Scope | Phase 1 behavior |
|--------|-------|------------------|
| Quick | High-risk user and system locations | Same roots as Risky Spots in Phase 1; process-path scanning is deferred |
| Full | All fixed, removable, and mounted drives visible to the scanner | Broadest scan; slower and more I/O intensive |
| Risky Spots | Temp, AppData, Downloads, Startup, System32, and Windows Temp | Focuses on common malware drop and persistence locations |

The GUI is designed to show a circular progress ring, live scanned-file stream,
Scanned/Malicious/Elapsed metrics, and a filterable results table after a scan
finishes.

## Signatures

The repository includes a bundled signature set under [`signatures/`](signatures):

```text
signatures/
|-- hashes.txt
|-- MANIFEST.json
|-- NOTICE.md
|-- licenses/
`-- rules/
    |-- bundled.yar
    `-- bundled.yarc
```

The bundled YARA set currently contains 13,134 compile-verified rules generated
from ReversingLabs, Yara-Rules, and bartblaze sources. See
[`signatures/NOTICE.md`](signatures/NOTICE.md) for attribution and GPL-2.0
obligations that apply to the bundled rule set.

Custom signatures use the same source layout:

- `hashes.txt` contains one SHA-256 hash per line. Blank lines and comments are
  ignored.
- `rules/*.yar` contains YARA source rules.
- After first import, the app seals signatures into an encrypted bundle.

## Results

Phase 1 stores signed, append-only JSONL results in:

```text
%ProgramData%\PowerScanner\results\
```

Each result line is HMAC-SHA256 signed. Verification detects edits, deletion of
line content, or forged result lines that do not have a valid machine-derived
signature.

## Security model and limitations

PowerScanner uses authenticated encryption or authenticated signatures for
persisted security-sensitive files.

- Signature bundles are encrypted at rest with AES-256-GCM using a
  machine-derived key.
- Result lines are signed with HMAC-SHA256 using a separate machine-derived key.
- Auth failures are treated as tamper evidence, not silently ignored.
- Source must not contain hardcoded keys or plaintext secrets.

Important limitations:

- Endpoint-side rule encryption raises the cost of extracting rules, but it
  cannot make extraction impossible on a machine the attacker controls. The app
  must decrypt rules in memory to scan with them.
- Result signing makes local tampering detectable, not preventable. Malware with
  local filesystem access may still delete or corrupt files; verification is how
  tampering is detected.

## Documentation

- [`docs/PRD.md`](docs/PRD.md) - product requirements.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - planned crate/module design.
- [`docs/SECURITY.md`](docs/SECURITY.md) - threat model and crypto rules.
- [`docs/PLAN.md`](docs/PLAN.md) - task index and execution model.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - later phases.
- [`tasks/`](tasks) - implementation task board.
