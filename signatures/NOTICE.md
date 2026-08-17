# Bundled YARA Rules — Attribution & Licenses

The file `rules/bundled.yar` is a merged, compile-verified collection of YARA
rules aggregated from three upstream open-source repositories. It was produced
by a filtering pipeline that (1) compile-tests every source file under
YARA-X, dropping files that fail to compile, (2) removes duplicate rule names,
and (3) removes false-positive-prone helper/utility rules. See
`docs/SIGNATURES.md` for the exact pipeline.

## Sources & licenses

| Upstream | License | Files kept | License text |
|----------|---------|-----------|--------------|
| [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules) (branch `develop`) | MIT | 310 | `licenses/LICENSE.reversinglabs.txt` |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | GPL-2.0 | 455 | `licenses/LICENSE.yara-rules.txt` |
| [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) (branch `master`) | MIT | 110 | `licenses/LICENSE.bartblaze.txt` |

Total: 875 source files, 13,134 rules.

## GPL-2.0 obligation (important)

Because this bundle includes rules from `Yara-Rules/rules`, which is licensed
under **GPL-2.0**, the combined `bundled.yar` file is a derivative work
governed by GPL-2.0. When distributing this rule bundle you MUST:

1. Keep this NOTICE and all files under `licenses/` alongside the bundle.
2. Make the corresponding source form of the bundle (`bundled.yar`) available
   to recipients.
3. Not impose restrictions beyond those of the GPL-2.0 on the rule bundle
   itself.

The GPL-2.0 obligation applies to the **rule bundle**, not necessarily to the
PowerScanner application binary that merely loads it at runtime. If you intend
to ship PowerScanner commercially and want to avoid the GPL-2.0 obligation on
your signature bundle, rebuild the bundle from MIT-only sources
(ReversingLabs + bartblaze) — see `docs/SIGNATURES.md`.

## Rules removed as false-positive-prone

The following `Yara-Rules/rules` categories were excluded because they match
generic content (URLs, IPs, email structure, generic capabilities) rather than
malware, and produced false positives when scanning an entire system:
`utils/`, `deprecated/`, `email/`, `capabilities/`.

## Rules dropped as incompatible

57 source files were dropped because they require the `androguard` YARA module
(Android APK analysis), which YARA-X does not implement. These are irrelevant
to a Windows file scanner.
