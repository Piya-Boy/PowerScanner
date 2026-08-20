# Security

## Threat model
Two threats are documented for Phase 1:

1. **Offline or accidental tampering** with scan results/logs.
   → Addressed with HMAC-SHA256 signed, append-oriented results in an
   ACL-protected directory (`%ProgramData%\PowerScanner\results`). Verification
   detects edits to surviving lines that do not reproduce the derived key. This
   is tamper-EVIDENT, not tamper prevention: a local process that can read the
   machine identifiers can derive the same key and forge a valid HMAC.
2. **Someone extracting the rule set** to resell it.
   → Raised in cost via AES-256-GCM at-rest encryption with an app-embedded
   (portable) bundle key. **Weak** — the key lives in the binary, so a
   determined reverse engineer recovers the rules. This is an accepted trade
   to keep the product installable with Windows Defender enabled. Stated
   honestly in README.

## Crypto design
- **Key derivation (results):** Argon2id over the machine identifier (Windows
  `MachineGuid` plus system-volume serial) with `RESULT_SALT`. Used for HMAC
  result signing; this binds the signing key to an installation.
- **Key derivation (signature bundle):** Argon2id over an app-embedded secret
  with `BUNDLE_SALT` — a PORTABLE key, deterministic across machines. This
  lets the shipped `bundle.psenc` decrypt on any host while shipping no
  plaintext YARA rules (plaintext rules can trip Windows Defender). The
  embedded secret is assembled from split byte arrays at runtime: obfuscation,
  not a real secret. Rule-set extraction protection is therefore
  obfuscation-grade only.
- **At-rest encryption:** AES-256-GCM. Blob layout `[12-byte nonce][ct+tag]`.
  Random nonce per encryption. Auth failure = tamper = error (never silent).
- **Result signing:** HMAC-SHA256 per JSONL line; constant-time verify.
- **No machine-bound or plaintext production secrets** are stored in source.
  The portable bundle key is intentionally embedded and documented as an
  extraction-cost measure, not a trust anchor.

Per-line HMACs do not authenticate complete-file membership: deleting or
truncating a complete valid line leaves the remaining lines valid. A chained
sequence number or external checkpoint is required for deletion detection and
is outside the current Phase 1 signer.

## Hard rules (enforced in review)
- Authenticated encryption or authenticated signatures on every persisted file.
- No plaintext secrets.
- No string concatenation into any query/command.
- No `unwrap()`/`expect()` in library paths (tests excepted).

## Lessons from reference project (SoSecure Insight)
Avoid its known defects: SQL injection via string concat, hardcoded license keys
in source, `|| 1==1` authentication bypasses. PowerScanner does none of these.

## Honest limitations (must appear in README)
- Endpoint-side rule encryption ≠ unbreakable. It raises cost; it cannot make
  extraction impossible on a machine the attacker controls.
- Result signing makes local tampering **detectable**, not **preventable**.
