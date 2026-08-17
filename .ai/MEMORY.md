# Long-term Memory

## Architecture Decisions
- Rust cargo workspace: `core/` (UI-agnostic lib) + `gui/` (egui bin). Core must
  never depend on a GUI crate — keeps process/service/CLI reuse open for later.
- Detection layers: SHA-256 exact (O(1)) → YARA (yara-x, pure Rust) → fuzzy
  (ssdeep+TLSH, Phase 2). `DetectionKind` enum is the extension seam.
- `ResultSink` trait is the storage seam: Phase 1 = HMAC-signed JSONL; later =
  SQLite + server sink. No rewrite needed to add them.
- Crypto: AES-256-GCM vault + HMAC-SHA256 result signing, keys derived at runtime
  via Argon2id over machine identifier (MachineGuid + salt). No hardcoded keys.

## Known Problems
- yara-x does not implement the `androguard` module → 57 Android rules dropped
  from the bundle (irrelevant to a Windows scanner).
- `yr` CLI (yara-x) can print an error yet still exit 0 in some invocations;
  the rule pipeline relies on exit code from isolated single-file compiles, which
  does return non-zero on failure.

## Important Lessons
- "Take all YARA rules" is wrong: 13k+ rules from mixed repos produced
  false-positives on clean files (rule `domain`/`IP` from `utils/`,
  plus `email/`, `capabilities/`, `deprecated/`). Dropping those categories
  removed FP on clean files while keeping EICAR detection. Bundle = 875 files /
  13,134 rules, compile-verified, FP-pruned.
- Endpoint-side encryption cannot be "100% unbreakable" — the app must hold the
  key to read its own rules, so a determined reverse engineer can extract them.
  What IS 100% achievable: tamper-EVIDENT results via HMAC (malware can't forge
  a valid signature). Framed honestly in README limitations.

## Failed Approaches
- Merging all rule files raw → name collisions and includes break compilation.
  Fix: compile-test each file in isolation, drop failures, dedupe rule names,
  then merge + verify-compile the whole set.

## Development Conventions
- TDD per the plan: failing test → run → minimal impl → pass → commit.
- Conventional Commits. No `Co-Authored-By` trailer (per user global prefs).
- Author = git user only.

## Security Lessons
- Reference project SoSecure Insight had SQL injection everywhere (string concat),
  hardcoded license keys, and `|| 1==1` auth bypasses. PowerScanner explicitly
  avoids all three: parameterized handling, machine-derived keys, no bypass flags.

## Licensing
- Rule bundle includes GPL-2.0 (`Yara-Rules/rules`) → the bundle is GPL-2.0;
  ship NOTICE + licenses/. MIT-only rebuild path documented for commercial use
  without the GPL obligation.
