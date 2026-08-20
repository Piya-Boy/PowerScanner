# Signature Files

PowerScanner loads the pre-sealed `signatures/bundle.psenc` shipped beside the
executable. Maintainers regenerate plaintext sources with
`tools/build-rules.sh`, then run `cargo run -p seal-bundle -- signatures`; the
plaintext rules remain build inputs and are not copied into a release. A local
development checkout may still use the first-run import path by removing
`bundle.psenc` and providing `hashes.txt` plus `rules/*.yar`.

## Hashes

`hashes.txt` contains one SHA-256 digest per line. Digests are expected in
lowercase hexadecimal form; blank lines and lines beginning with `#` are
ignored. Example:

```text
# known test sample
275a021bbfb6489e54d471899f7db0d2f7f8f4a1f0c5d7b7c7a1c9a8c7b6d5e4
```

The hash database is an exact-match blacklist. An entirely empty or
whitespace-only file is rejected during first-run import; comment-only files are
allowed when YARA rules provide the active detections.

## YARA Rules

Place UTF-8 YARA source files in `rules/` with a `.yar` or `.yara` extension.
Each source set must contain at least one compilable `rule` declaration. Minimal
example:

```yara
rule PowerScanner_TestMarker {
    strings:
        $marker = "POWERSCANNER_TEST"
    condition:
        $marker
}
```

Unreadable or syntactically invalid sources are rejected. The complete source
set must contain at least one effective `rule` declaration; blank or
comment-only files are ignored when a valid rule exists, and a set containing
only such files is rejected. Rule compilation happens before files are scanned.

## Bundle Behavior

`bundle.psenc` is an AES-256-GCM encrypted JSON bundle containing `hashes_text`
and the YARA source list. Its portable Argon2id-derived key is embedded in the
application so a shipped bundle opens on any host. This is deliberate
obfuscation to avoid shipping plaintext rules, not a secret trust anchor: a
determined reverse engineer can recover rules from a machine running the app.

Signed scan results are appended to `results.jsonl` under
`%ProgramData%\PowerScanner\results` on Windows (a private temporary fallback
is used when the known-folder environment is unavailable). Each record is
HMAC-SHA256 authenticated and the writer/verifier use cross-process file locks.
