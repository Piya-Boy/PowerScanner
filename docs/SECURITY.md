# Security

## Threat model
Two threats in scope for Phase 1:

1. **Malware on the box** tampering with or forging scan results/logs.
   → Addressed with HMAC-SHA256 signed, append-only results in an ACL-protected
   directory (`%ProgramData%\PowerScanner\results`). Malware cannot forge a valid
   signature without the machine-derived key. **This is 100% tamper-EVIDENT** —
   any alteration is detectable on verify.
2. **Someone extracting the rule set** to resell it.
   → Raised in cost via AES-256-GCM at-rest encryption + machine-derived key +
   in-memory decryption. **Not 100%** — the app must decrypt to use rules, so a
   determined reverse engineer can recover them. Stated honestly in README.

## Crypto design
- **Key derivation:** Argon2id over the machine identifier (Windows `MachineGuid`
  from registry) with a fixed per-purpose salt. Distinct salts for signature
  vault (`SIG_SALT`) and result signing (`RESULT_SALT`).
- **At-rest encryption:** AES-256-GCM. Blob layout `[12-byte nonce][ct+tag]`.
  Random nonce per encryption. Auth failure = tamper = error (never silent).
- **Result signing:** HMAC-SHA256 per JSONL line; constant-time verify.
- **No hardcoded keys or secrets** anywhere in source.

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
