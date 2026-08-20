#!/usr/bin/env bash
# Reproducible YARA-X rule bundle builder.
# Usage: tools/build-rules.sh [--self-test]
set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_WORK="$REPO_ROOT/.rule-build"
WORK="${PS_RULE_WORK:-$DEFAULT_WORK}"
SRC="$WORK/yara-src"
OUT="$WORK/out"
SIGDIR="$REPO_ROOT/signatures"
YR="${YR:-yr}"
SOURCES="$REPO_ROOT/tools/rule-sources.txt"
FP_PRONE_GLOBS='yara-rules_utils_* yara-rules_deprecated_* yara-rules_email_* yara-rules_capabilities_*'

extract_rule_names() {
  awk '
    BEGIN { in_block = 0; in_quote = 0; in_regex = 0; escaped = 0; sig = "" }
    {
      line = $0
      out = ""
      for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        n = substr(line, i + 1, 1)
        if (in_block) {
          if (c == "*" && n == "/") { in_block = 0; i++ }
          continue
        }
        if (in_quote) {
          out = out c
          if (escaped) escaped = 0
          else if (c == "\\") escaped = 1
          else if (c == "\"") in_quote = 0
          if (c !~ /[[:space:]]/) sig = c
          continue
        }
        if (in_regex) {
          out = out c
          if (escaped) escaped = 0
          else if (c == "\\") escaped = 1
          else if (c == "/") in_regex = 0
          if (c !~ /[[:space:]]/) sig = c
          continue
        }
        if (c == "\"" ) { in_quote = 1; escaped = 0; out = out c; sig = c; continue }
        if (c == "/" && n == "*") { in_block = 1; i++; continue }
        if (c == "/" && n == "/") break
        if (c == "/" && sig ~ /^[=(:,!\[]$/) { in_regex = 1; escaped = 0; out = out c; sig = c; continue }
        out = out c
        if (c !~ /[[:space:]]/) sig = c
      }
      print out
    }
  ' "$1" \
    | grep -aoE '^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' \
    | sed -E 's/.*rule[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/' \
    | sort -u || true
}

is_fp_prone() {
  local name="$1" glob
  for glob in $FP_PRONE_GLOBS; do
    case "$name" in $glob) return 0 ;; esac
  done
  return 1
}

self_test() {
  local temp got
  temp="$(mktemp -d)"
  printf '/* true\n   rule Hidden { condition: true }\n*/\nrule Foo_Bar { condition: true }\nprivate rule Baz { condition: true }\nrule StringMarkers { strings: $s = "/* // */" condition: $s }\nrule RegexMarkers { strings: $r = /a\\/\\*b\\/\\// condition: $r }\n' > "$temp/a.yar"
  got="$(extract_rule_names "$temp/a.yar" | tr '\n' ',')"
  rm -rf "$temp"
  [ "$got" = "Baz,Foo_Bar,RegexMarkers,StringMarkers," ] || { echo "FAIL extract_rule_names: got '$got'" >&2; return 1; }
  is_fp_prone "yara-rules_utils_ip.yar" || { echo "FAIL is_fp_prone utils" >&2; return 1; }
  if is_fp_prone "reversinglabs_trojan_x.yara"; then echo "FAIL is_fp_prone false-hit" >&2; return 1; fi
  echo "self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi

command -v git >/dev/null 2>&1 || { echo "git required" >&2; exit 1; }
command -v "$YR" >/dev/null 2>&1 || { echo "yara-x CLI '$YR' required (cargo install yara-x-cli)" >&2; exit 1; }
[ "$WORK" = "$DEFAULT_WORK" ] || {
  echo "PS_RULE_WORK is disabled; the build workspace is fixed at $DEFAULT_WORK" >&2
  exit 1
}
rm -rf -- "$DEFAULT_WORK"
mkdir -p "$SRC" "$OUT/passed" "$OUT/publish" "$SIGDIR/rules"
ref_rl=""; ref_yr=""; ref_bb=""

while IFS=$'\t' read -r dir url ref license; do
  case "$dir" in ''|'#'*) continue ;; esac
  echo ">> fetch $dir ($ref, $license)"
  git init "$SRC/$dir" >/dev/null
  git -C "$SRC/$dir" config core.autocrlf false
  git -C "$SRC/$dir" remote add origin "$url"
  git -C "$SRC/$dir" fetch --depth 1 origin "$ref" >/dev/null
  git -C "$SRC/$dir" checkout --detach FETCH_HEAD >/dev/null
  resolved="$(git -C "$SRC/$dir" rev-parse HEAD)"
  [ "$resolved" = "$ref" ] || { echo "FATAL: ref mismatch for $dir" >&2; exit 1; }
  case "$dir" in
    reversinglabs) ref_rl="$resolved" ;;
    yara-rules) ref_yr="$resolved" ;;
    bartblaze) ref_bb="$resolved" ;;
  esac
done < "$SOURCES"

mapfile -t files < <(find "$SRC" -type f \( -iname '*.yar' -o -iname '*.yara' \) ! -iname '*index*' | sort)
declare -A seen
pass=0; fail=0; dupe=0; fp=0
: > "$OUT/skipped.log"
for file in "${files[@]}"; do
  if ! "$YR" compile "$file" -o "$OUT/.probe.yarc" >/dev/null 2>&1; then
    printf 'COMPILE_FAIL\t%s\n' "$file" >> "$OUT/skipped.log"; fail=$((fail + 1)); continue
  fi
  base="$(printf '%s' "$file" | sed -E 's#.*/yara-src/##; s#[/ ]#_#g')"
  if is_fp_prone "$base"; then
    printf 'FP_PRONE\t%s\n' "$file" >> "$OUT/skipped.log"; fp=$((fp + 1)); continue
  fi
  conflict=""
  while read -r name; do
    if [ -n "${seen[$name]:-}" ]; then conflict="$name"; break; fi
  done < <(extract_rule_names "$file")
  if [ -n "$conflict" ]; then
    printf 'DUPE(%s)\t%s\n' "$conflict" "$file" >> "$OUT/skipped.log"; dupe=$((dupe + 1)); continue
  fi
  while read -r name; do [ -n "$name" ] && seen[$name]=1; done < <(extract_rule_names "$file")
  [ ! -e "$OUT/passed/$base" ] || { echo "FATAL: flattened filename collision: $base" >&2; exit 1; }
  cp "$file" "$OUT/passed/$base"
  pass=$((pass + 1))
done

find "$OUT/passed" -type f \( -name '*.yar' -o -name '*.yara' \) -print0 \
  | sort -z \
  | while IFS= read -r -d '' file; do cat "$file"; done > "$OUT/publish/bundled.yar"
"$YR" compile "$OUT/publish/bundled.yar" -o "$OUT/publish/bundled.yarc" >/dev/null 2>"$OUT/merge_err.txt"
rules="$(extract_rule_names "$OUT/publish/bundled.yar" | wc -l | tr -d ' ')"
[ "$rules" -gt 0 ] || { echo "FATAL: merged bundle contains no rules" >&2; exit 1; }
sha_yar="$(sha256sum "$OUT/publish/bundled.yar" | awk '{print $1}')"
sha_yarc="$(sha256sum "$OUT/publish/bundled.yarc" | awk '{print $1}')"
sha_hashes="$(sha256sum "$SIGDIR/hashes.txt" | awk '{print $1}')"
kept_rl="$(find "$OUT/passed" -maxdepth 1 -type f -name 'reversinglabs_*' | wc -l | tr -d ' ')"
kept_yr="$(find "$OUT/passed" -maxdepth 1 -type f -name 'yara-rules_*' | wc -l | tr -d ' ')"
kept_bb="$(find "$OUT/passed" -maxdepth 1 -type f -name 'bartblaze_*' | wc -l | tr -d ' ')"
yrver="$("$YR" --version | awk '{print $2}')"
version="$(cat "$SIGDIR/.bundle-date")"
[[ "$version" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$ ]] || { echo "FATAL: invalid signatures/.bundle-date" >&2; exit 1; }
cat > "$OUT/publish/MANIFEST.json" <<JSON
{
  "bundle_version": "$version",
  "generated_from": [
    { "repo": "reversinglabs/reversinglabs-yara-rules", "ref": "$ref_rl", "license": "MIT", "files_kept": $kept_rl },
    { "repo": "Yara-Rules/rules", "ref": "$ref_yr", "license": "GPL-2.0", "files_kept": $kept_yr },
    { "repo": "bartblaze/Yara-rules", "ref": "$ref_bb", "license": "MIT", "files_kept": $kept_bb }
  ],
  "excluded_anyrun": "anyrun/YARA - no LICENSE file, excluded",
  "total_files": $pass,
  "total_rules": $rules,
  "yara_x_version": "$yrver",
  "pipeline": "compile-test per file, drop FP-prone categories, dedupe rule names",
  "artifacts": {
    "hashes.txt": { "sha256": "$sha_hashes" },
    "bundled.yar": { "sha256": "$sha_yar" },
    "bundled.yarc": { "sha256": "$sha_yarc", "note": "precompiled YARA-X rules" }
  }
}
JSON
backup="$OUT/backup"
mkdir -p "$backup"
for target in "$SIGDIR/rules/bundled.yar" "$SIGDIR/rules/bundled.yarc" "$SIGDIR/MANIFEST.json"; do
  if [ -e "$target" ]; then cp "$target" "$backup/$(basename "$target")"; fi
done
published=()
rollback() {
  set +e
  for target in "${published[@]}"; do
    old="$backup/$(basename "$target")"
    if [ -e "$old" ]; then cp "$old" "$target"; else rm -f -- "$target"; fi
  done
  rm -f -- "$SIGDIR/rules/bundled.yar.new" "$SIGDIR/rules/bundled.yarc.new" "$SIGDIR/MANIFEST.json.new"
}
cleanup_on_exit() {
  status=$?
  if [ "$status" -ne 0 ]; then rollback; fi
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$OUT/publish/bundled.yar" "$SIGDIR/rules/bundled.yar.new"
cp "$OUT/publish/bundled.yarc" "$SIGDIR/rules/bundled.yarc.new"
cp "$OUT/publish/MANIFEST.json" "$SIGDIR/MANIFEST.json.new"
published+=("$SIGDIR/rules/bundled.yar")
mv -f "$SIGDIR/rules/bundled.yar.new" "$SIGDIR/rules/bundled.yar"
published+=("$SIGDIR/rules/bundled.yarc")
mv -f "$SIGDIR/rules/bundled.yarc.new" "$SIGDIR/rules/bundled.yarc"
published+=("$SIGDIR/MANIFEST.json")
mv -f "$SIGDIR/MANIFEST.json.new" "$SIGDIR/MANIFEST.json"
trap - EXIT INT TERM
echo "kept=$pass fail=$fail fp=$fp dupe=$dupe rules=$rules"
echo "MANIFEST.json refreshed"
