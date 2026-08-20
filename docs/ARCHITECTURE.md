# Architecture

Security-first architecture spanning all three delivery phases. This is the
system-level map; task-level design and code live in the two implementation
plans under `docs/superpowers/plans/`. Where this document and an older doc
disagree, this document is authoritative and the discrepancy is called out
inline.

- Phase 1 — standalone scanner (`core` + `gui`). See `2026-08-17-powerscanner-phase1.md`.
- Phase 3 — auto-updater (`updater`). See `2026-08-17-powerscanner-updater.md`.
- Phase 2/4 — depth + advanced detection, additive on Phase 1 seams (ROADMAP).

---

## 1. System overview & trust boundaries

PowerScanner is a Windows x64, low-footprint, on-demand malware scanner. Three
processes cooperate, each with a distinct privilege level and trust boundary:

```
                          ┌──────────────────────────── Windows host ─────────────────────────────┐
                          │                                                                        │
   ┌──────────────┐       │   ┌─────────────────────┐        ┌──────────────────────────────────┐ │
   │ GitHub        │ https │   │ powerscanner.exe    │        │ %ProgramData%\PowerScanner\       │ │
   │ Releases      │◄──────┼───┤ (GUI, user rights)  │────────┤   results\   (ACL: SYSTEM+Admins) │ │
   │ (untrusted    │       │   │  core engine (lib)  │  write │   cache\                          │ │
   │  network src) │       │   └─────────┬───────────┘ signed └──────────────────────────────────┘ │
   └──────┬────────┘       │             │ read (in-mem decrypt)                                    │
          │                │             ▼                                                          │
          │ https poll     │   ┌─────────────────────┐        ┌──────────────────────────────────┐ │
   ┌──────┴────────┐       │   │ signatures\         │        │ scan targets (filesystem)         │ │
   │ psupdater-svc │───────┼──►│  bundle.psenc       │        │  Quick / Full / Risky presets     │ │
   │ (SYSTEM svc)  │ atomic│   │  MANIFEST.json      │◄───────┤  READ-ONLY, treated as HOSTILE    │ │
   │ Ed25519+SHA256│replace│   │  .sig-hwm / .app-hwm│  scan  │  (files may be live malware)      │ │
   └───────────────┘       │   └─────────────────────┘        └──────────────────────────────────┘ │
                          │                                                                        │
                          └────────────────────────────────────────────────────────────────────────┘
```

### Trust boundaries (numbered; referenced by the threat model in §4)

- **TB-1 — Network ↔ host.** GitHub Releases is an *untrusted* content source
  reachable only by `psupdater-svc`. Everything crossing TB-1 is unauthenticated
  until it passes Ed25519 + SHA-256 verification. Fail-closed.
- **TB-2 — Scan target ↔ engine.** Files under scan are treated as *hostile
  input*: potentially live malware, crafted to exploit the parser. The engine
  never executes, maps, or trusts scanned content; it only hashes and pattern-
  matches with bounded reads.
- **TB-3 — Signature bundle at rest ↔ engine.** `bundle.psenc` is AES-256-GCM
  ciphertext. It is authenticated on decrypt; a GCM tag failure is a hard error,
  never a silent fallback. Rules exist in plaintext only in process memory.
- **TB-4 — Results at rest ↔ everyone else on the box.** Result files are
  HMAC-signed and live in an ACL-restricted directory. Any local process
  (including malware) may *read* them, but cannot forge a valid signature nor
  alter a line undetectably.
- **TB-5 — Service (SYSTEM) ↔ app (user).** `psupdater-svc` runs as SYSTEM and
  writes into the install dir; the GUI runs with user rights. The only data the
  service accepts from the app side is the plaintext `app.version` file, which is
  advisory only (a lie there at worst forces a re-verified update, never a
  downgrade — see S2).

### Privilege model

| Process           | Runs as        | Can write                              | Trusts                          |
|-------------------|----------------|----------------------------------------|---------------------------------|
| `powerscanner.exe`| invoking user  | results\, cache\ (via ACL)             | verified bundle, machine key    |
| `psupdater-svc`   | LocalSystem    | install dir, signatures\               | Ed25519 pubkey (embedded) only  |
| `psupdater-sign`  | maintainer, offline | release manifest.sig             | offline private key             |

---

## 2. Crate & module map

Cargo workspace, three crates. `core` is UI-agnostic and depends on no GUI crate
(`eframe`/`egui`/`winit`) so a future CLI/service can reuse it (ADR-001).

```
powerscanner/
├─ core/     # engine library — scan, crypto, signatures, sink
├─ gui/      # eframe/egui binary — depends on core
└─ updater/  # Phase 3: service + offline signing tools — depends on core (PsError)
```

### `core` — engine (no UI, no network)

- **`error`** — `PsError` (thiserror) with variants `Io`, `Crypto`, `Signature`,
  `Yara`, `Config`, `Tamper`; `PsResult<T> = Result<T, PsError>`. `Tamper` vs
  `Signature` is deliberate: `Tamper` marks an authenticated-data mismatch on
  something we wrote (results), `Signature` marks a verification failure on
  something we received (manifest).
- **`crypto/`** — the security core.
  - `machine_key` — Argon2id KDF over `MachineGuid` (registry) **+ volume serial**,
    with a distinct per-purpose salt (`SIG_SALT` for the vault, `RESULT_SALT` for
    the signer). *Discrepancy note:* `docs/SECURITY.md` describes MachineGuid + a
    fixed salt only; the Phase 1 plan additionally binds the volume serial. The
    plan is authoritative — binding the volume serial ties the key to the disk,
    not just the OS install, raising extraction cost. SECURITY.md to be updated.
  - `vault` — AES-256-GCM. Blob layout `[12-byte random nonce][ciphertext‖tag]`.
    Fresh nonce per encryption; auth failure ⇒ `PsError::Crypto`, never plaintext.
  - `signer` — HMAC-SHA256 sign/verify, **constant-time** compare, over each
    persisted result line.
- **`signatures/`** — detection data.
  - `hashdb` — SHA-256 blacklist loaded into a `HashSet` for O(1) lookup.
  - `rules` — `yara-x` compile/hold/scan (ADR-002; pure Rust, no C libyara).
  - `store` — first-run import of `hashes.txt` + `rules/*.yar`, then sealed as the
    single encrypted `bundle.psenc`. **C4:** reads the sealed bundle fully into
    memory and drops the file handle immediately, so the updater service can
    atomically replace the file without a sharing-violation clash.
- **`scan/`** — orchestration.
  - `targets` — Quick / Full / Risky-Spots preset → concrete roots.
  - `walk` — enumerate files (walkdir), skip reparse points/symlinks to avoid
    traversal loops and out-of-scope escapes.
  - `incremental` — skip files whose `(size, mtime)` are unchanged since last scan.
  - `hasher` — streaming SHA-256 (bounded buffer, never loads whole file for hash).
  - `engine` — rayon parallel fan-out; per file: hash → hashdb lookup → YARA
    (capped 16 MiB in-memory read) → `ScanResult`.
  - `result` — `ScanResult`, `Verdict`, `Finding`, `DetectionKind` (seam).
- **`sink/`** — `ResultSink` trait; `jsonl` writes HMAC-signed append-only JSONL.

### `gui` — presentation

- `main.rs` — eframe bootstrap; writes `app.version` at startup (updater seam).
- `app.rs` — `Phase`/`AppState`/`ScanMsg`/`StreamLine`; background scan thread,
  `mpsc` channel to UI (scan never blocks the frame loop).
- `ring.rs` — `Painter`-drawn circular progress ring (ADR-003).

### `updater` — Phase 3 (Windows service + offline tools)

- `manifest` — `UpdateManifest` + `canonical_bytes()` (deterministic, sorted-key
  JSON: signer and verifier must produce identical bytes).
- `verify` — Ed25519 verify against embedded `UPDATE_PUBLIC_KEY` + SHA-256 asset
  digest. Fail-closed.
- `version` — fail-closed version compare (garbage ⇒ error, never "newer").
- `github` — Releases client; https-only, size-capped, channel-split by tag prefix.
- `apply` — atomic replace with `.bak`, rollback, staged `.new` exe swap.
- `config` — repo/owner constants, 6h poll default, install-dir resolution,
  local-version + high-water-mark reads.
- `orchestrate` — the pure core: fetch → verify signature → **channel binding
  (S1)** → asset-name check → **anti-downgrade high-water mark (S2)** → digest →
  apply. Network abstracted behind a `Fetcher` trait for offline unit tests.
- `service` — Windows Service host (SCM), 6h poll loop, app stop-swap-relaunch.
- `bin/` — `psupdater-svc` (service), `psupdater-sign` + `psupdater-keygen`
  (offline maintainer tools; the **private key never enters the repo or binary**).

---

## 3. Data flow

### Scan (Phase 1)

```
preset ─► resolve roots ─► walk (skip symlinks) ─► incremental filter (size+mtime)
       ─► [rayon parallel, per file] ──────────────────────────────────────────────┐
                                                                                    │
   hash (streaming SHA-256) ─► hashdb lookup ─┬─ hit  ─► Verdict::Malicious         │
                                              └─ miss ─► YARA scan (≤16 MiB) ─┬─ hit │
                                                                             └─ miss│
                                                                    ─► Verdict::Clean│
       ◄────────────────────────────────────────────────────────────────────────────┘
   ScanResult ─► ResultSink (HMAC-signed JSONL, append-only, ACL dir)
             └─► mpsc ─► GUI (live stream while scanning ► result table when done)
```

Fail-safe posture: an unreadable/locked file yields an *error finding*, never a
false "clean" — absence of detection is never reported as proof of cleanliness.

### Update (Phase 3) — sign-before-trust ordering is mandatory

```
psupdater-svc every 6h, per channel {sig, app}:
  GET releases (https) ─► pick tag by channel prefix ─► resolve 3 asset URLs (https only)
    ─► download manifest.json + manifest.json.sig
    ─► (1) Ed25519 verify manifest.sig ───────────────► FAIL ⇒ discard
    ─► (2) channel binding: manifest.channel == this ─► FAIL ⇒ discard   [S1]
    ─► (3) asset_name == channel asset ───────────────► FAIL ⇒ discard
    ─► (4) is_newer(version, max(hwm, local)) ────────► NO   ⇒ up-to-date [S2]
    ─► download asset ─► (5) SHA-256 == manifest.sha256_hex ─► FAIL ⇒ discard
    ─► apply:
         sig ► atomic_replace(bundle.psenc) w/ retry ► advance sig hwm
         app ► stage .new ► stop app + wait lock clear ► swap ► rollback-on-fail
              ► advance app hwm ► relaunch                                  [C1]
```

No manifest field is trusted before step (1) succeeds. Steps (2)–(5) still run
even on a validly-signed manifest — signature proves *authenticity*, not that
this is the right channel, the newest version, or an intact download.

---

## 4. Security architecture

### 4.1 Cryptographic design

| Purpose             | Primitive        | Key / trust anchor                          | Failure mode        |
|---------------------|------------------|---------------------------------------------|---------------------|
| Rule DB at rest     | AES-256-GCM      | machine key (Argon2id, `SIG_SALT`)          | tag fail ⇒ error    |
| Result integrity    | HMAC-SHA256      | machine key (Argon2id, `RESULT_SALT`)       | mismatch ⇒ `Tamper` |
| Update authenticity | Ed25519          | embedded public key; private key **offline**| verify fail ⇒ drop  |
| Asset integrity     | SHA-256          | digest inside the *signed* manifest         | mismatch ⇒ drop     |

- **Key derivation.** Argon2id over `MachineGuid` + volume serial + per-purpose
  salt. No key material in source (ADR-004). Distinct salts guarantee the vault
  key and the signing key are independent even though both derive from the same
  machine identity.
- **Nonce discipline.** Random 96-bit nonce per GCM encryption, stored beside the
  ciphertext. Never reused, never derived from data.
- **Constant-time.** HMAC verification and any digest/tag comparison use
  constant-time equality to avoid timing oracles.
- **Determinism where it matters.** `UpdateManifest::canonical_bytes()` fixes
  key order so signer and verifier agree byte-for-byte; a mismatch here would
  silently break verification, so it is unit-tested for stability.

### 4.2 Threat model (by trust boundary)

| # | Threat (STRIDE)                                   | Boundary | Mitigation |
|---|---------------------------------------------------|----------|------------|
| T1| Malware forges/alters scan results (Tampering)    | TB-4     | HMAC-SHA256 per line + ACL dir. Tamper-**evident**, not preventable — stated honestly. |
| T2| Attacker extracts the rule set to resell (Info)   | TB-3     | AES-256-GCM + machine-bound key + in-memory-only plaintext. Cost-raising, **not** absolute on an attacker-controlled box. |
| T3| Forged/MITM'd update (Spoofing/Tampering)         | TB-1     | Ed25519-signed manifest verified before any field is trusted; SHA-256 per asset; https-only. Fail-closed. |
| S1| Cross-channel manifest swap (validly signed)      | TB-1     | Manifest `channel` + `asset_name` bound to the requested channel; other-channel manifest rejected. |
| S2| Replay of an older, validly-signed vulnerable ver | TB-1     | Per-channel high-water mark of the greatest version ever applied; anything ≤ hwm refused even if signed. |
| C1| App-swap race / half-applied binary               | TB-5     | Stop app, **wait (≤30s) for file-lock release**, swap, rollback-on-failure. Never a partial exe. |
| C4| Service replaces bundle while GUI reads it        | TB-3/TB-5| GUI reads bundle to memory + drops handle immediately; service retries the atomic replace (bounded backoff). |
| T4| Malicious scan input exploits the parser          | TB-2     | Bounded reads (16 MiB YARA cap, streaming hash), no execution/mapping, yara-x (memory-safe Rust). |
| T5| Path traversal / symlink escape during walk       | TB-2     | Skip reparse points/symlinks; presets resolve to concrete roots; no path built from remote input. |
| T6| Untrusted repo path/URL injection                 | TB-1     | Reject owner/repo containing `/`, whitespace; reject any non-`https` asset URL; size cap on downloads. |

### 4.3 Attack surface & standing rules

- **No hardcoded secrets** anywhere (public key is not a secret; private key is
  offline). Enforced in review.
- **No `unwrap()`/`expect()`** in library/service code paths (tests excepted) —
  a panic is a denial-of-service and an information leak.
- **No string concatenation** into any command line, path, or (future) query
  from remote/untrusted input; allowlist-validate first.
- **Authenticated everything at rest** — every persisted file carries a GCM tag
  or an HMAC; no unauthenticated ciphertext, no plaintext secret.
- **Fail-closed** — verification failure (GCM tag, HMAC, Ed25519, SHA-256,
  version parse) discards the input; it is never treated as success or "newer".
- **Lessons from SoSecure Insight (reference project):** avoided its SQL-concat
  injection, hardcoded license keys, and `|| 1==1` auth bypass. The updater
  additionally fixes its manual-update flaw (stale signatures) with the signed,
  auto-applying service.

### 4.4 Honest limitations (must also appear in README)

- Endpoint-side rule encryption raises extraction cost; it cannot be unbreakable
  on a machine the attacker fully controls (T2).
- Result signing makes local tampering **detectable**, not **preventable** (T1).

---

## 5. Extension seams

Phase boundaries are chosen so later phases plug into Phase 1 interfaces without
a rewrite (ADR-006).

- **`DetectionKind` enum** — Phase 2 adds `Ssdeep` / `Tlsh` fuzzy-hash variants
  as detection layer 3 (run only on still-clean executables, a perf guard).
- **`ResultSink` trait** — Phase 1 ships `JsonlSink`; Phase 3 adds a SQLite sink
  and an agent→server sync sink behind the same trait.
- **`core` UI-agnosticism** — a CLI or service front-end can drive the engine
  with no change to `core`.
- **`bundle_version` / single `bundle.psenc` / `PsError`** — the exact seams the
  updater reuses; the updater adds no new coupling beyond the advisory
  `app.version` file written by the GUI.

---

## 6. Deployment & OS-level hardening

- **Install layout.** `%ProgramFiles%\PowerScanner\` holds `powerscanner.exe`,
  `psupdater-svc.exe`, `signatures\` (`bundle.psenc`, `MANIFEST.json`, hwm
  files), and `app.version`.
- **Results & cache.** `%ProgramData%\PowerScanner\results\` and `\cache\`,
  ACL-restricted to SYSTEM + Administrators (writable by the engine, readable by
  operators, not forgeable by a standard-user malware process).
- **Updater service.** `PowerScannerUpdater`, LocalSystem, auto-start, installed
  via `tools/install-updater.ps1` (idempotent, elevated). Polls every 6h,
  logs to `updater.log`, keeps `.bak` for rollback.
- **Signing key custody.** One-time `psupdater-keygen` on an offline machine;
  embed the printed public key in `updater/src/verify.rs`; store the private key
  offline. `*.key` is git-ignored. Releases are signed offline with
  `psupdater-sign`; see `docs/RELEASING.md` for the per-channel runbook.

---

## Reference

- Phase 1 task-level design + code: `docs/superpowers/plans/2026-08-17-powerscanner-phase1.md`
- Phase 3 updater design + code: `docs/superpowers/plans/2026-08-17-powerscanner-updater.md`
- Decisions: `docs/ADR.md` · Threat notes: `docs/SECURITY.md` · Roadmap: `docs/ROADMAP.md`
