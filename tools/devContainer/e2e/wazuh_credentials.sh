#!/usr/bin/env bash
# wazuh_credentials.sh — generate, check or clear the e2e stack credentials file.
#
# Writes the five passwords the e2e stack shares (indexer, dashboard, manager install) as plain
# KEY=value lines (no quotes, no spaces) to a 0600 file, by default <this dir>/.credentials.env
# (gitignored). docker compose reads it through env_file:, wazuh_install_manager.sh through ENVV.
#
# Password policy: this script generates and validates on its own and does NOT use the
# wazuh-credentials library — that library does not guarantee the symbol class and its validator
# accepts characters outside the transport alphabet (decision recorded in the plan's
# 03-diseno-credenciales.md §1). Each password is 28 random characters of the transport alphabet
# A-Za-z0-9.,_+:@%^=~- plus one lowercase, one uppercase, one digit and one symbol inserted at
# random positions: exactly 32 characters, all four classes guaranteed. Randomness: openssl rand,
# rejection sampling (no modulo bias).
#
# Output: one "PASS|FAIL|SKIP <check> — <detail>" line per check, then "# summary: N pass, M fail".
# Exit status 0 iff nothing failed. No password value is ever printed.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KEYS=(WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD
      WAZUH_MANAGER_API_PASSWORD WAZUH_MANAGER_WUI_PASSWORD)
LOWER=abcdefghijklmnopqrstuvwxyz
UPPER=ABCDEFGHIJKLMNOPQRSTUVWXYZ
DIGIT=0123456789
SYMBOL='.,_+:@%^=~-'
ALPHABET="${UPPER}${LOWER}${DIGIT}${SYMBOL}"
VALUE_RE='^[A-Za-z0-9.,_+:@%^=~-]{32}$'
export LC_ALL=C

usage() {
  cat <<USAGE
Usage: $0 [--file PATH] [--force | --clear | --check] [-h|--help]

  (no mode)     create the file if missing; if it exists and validates, leave it untouched (PASS);
                if it exists and does not validate, FAIL without regenerating
  --force       regenerate every password, overwriting the file
  --clear       delete the file (PASS if it does not exist)
  --check       list the keys present (names only) and validate; rc 1 if any is missing or invalid
  --file PATH   credentials file (default: $SCRIPT_DIR/.credentials.env)
USAGE
}

FILE="$SCRIPT_DIR/.credentials.env"
MODE=ensure
while [ $# -gt 0 ]; do
  case "$1" in
    --file) [ $# -ge 2 ] || { usage >&2; exit 2; }; FILE=$2; shift 2 ;;
    --force|--clear|--check)
      [ "$MODE" = ensure ] || { echo "only one of --force, --clear, --check" >&2; exit 2; }
      MODE=${1#--}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

NPASS=0
NFAIL=0
report() { # report PASS|FAIL|SKIP <check> <detail>
  printf '%s %s — %s\n' "$1" "$2" "$3"
  case "$1" in PASS) NPASS=$((NPASS + 1)) ;; FAIL) NFAIL=$((NFAIL + 1)) ;; esac
}
finish() {
  printf '# summary: %d pass, %d fail\n' "$NPASS" "$NFAIL"
  if [ "$NFAIL" -eq 0 ]; then exit 0; fi
  exit 1
}

# --- randomness: a pool of openssl bytes, consumed with rejection sampling ---
POOL=()
POS=0
refill() {
  mapfile -t POOL < <(openssl rand 512 | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
  POS=0
  [ "${#POOL[@]}" -gt 0 ] || { report FAIL openssl "openssl rand produced no bytes"; finish; }
}
rand_below() { # rand_below N -> REPLY uniform in [0, N)
  local n=$1 limit b
  limit=$((256 - 256 % n))
  while :; do
    [ "$POS" -lt "${#POOL[@]}" ] || refill
    b=${POOL[POS]}
    POS=$((POS + 1))
    if [ "$b" -lt "$limit" ]; then REPLY=$((b % n)); return 0; fi
  done
}
gen_password() { # gen_password -> PASSWORD
  local pw="" i set c
  for ((i = 0; i < 28; i++)); do
    rand_below "${#ALPHABET}"; pw+=${ALPHABET:REPLY:1}
  done
  for set in "$LOWER" "$UPPER" "$DIGIT" "$SYMBOL"; do
    rand_below "${#set}"; c=${set:REPLY:1}
    rand_below $((${#pw} + 1)); pw="${pw:0:REPLY}${c}${pw:REPLY}"
  done
  PASSWORD=$pw
}

# --- validation: sets REASONS (never contains a value) and PRESENT (key names found) ---
validate_file() {
  REASONS=()
  PRESENT=()
  local line key value n=0 k
  declare -A seen=()
  [ -f "$FILE" ] || { REASONS+=("file does not exist"); return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [[ $line == '#'* ]] && continue
    key=${line%%=*}
    value=${line#*=}
    if [[ $line != *=* ]] || [[ " ${KEYS[*]} " != *" $key "* ]]; then
      REASONS+=("line $n: not a comment nor one of the expected keys"); continue
    fi
    if [ -n "${seen[$key]:-}" ]; then REASONS+=("$key: duplicated (line $n)"); continue; fi
    seen[$key]=1
    PRESENT+=("$key")
    if [[ $value == *[\"\'\ ]* ]]; then REASONS+=("$key: contains quotes or spaces")
    elif [ "${#value}" -ne 32 ]; then REASONS+=("$key: length ${#value}, expected 32")
    elif ! [[ $value =~ $VALUE_RE ]]; then REASONS+=("$key: characters outside the transport alphabet")
    fi
  done <"$FILE"
  for k in "${KEYS[@]}"; do
    [ -n "${seen[$k]:-}" ] || REASONS+=("$k: missing")
  done
  [ "${#REASONS[@]}" -eq 0 ]
}
report_validation() { # after validate_file
  local r
  if [ "${#REASONS[@]}" -eq 0 ]; then
    report PASS validate "$FILE: ${#KEYS[@]} keys, 32 chars each, transport alphabet only"
  else
    for r in "${REASONS[@]}"; do report FAIL validate "$r"; done
  fi
}
report_mode() {
  local m
  m=$(stat -c %a "$FILE")
  if [ "$m" = 600 ]; then report PASS permissions "mode 0600"
  else report FAIL permissions "mode 0$m, expected 0600 (chmod 600 or --force)"; fi
}

generate() {
  command -v openssl >/dev/null || { report FAIL openssl "openssl not found in PATH"; finish; }
  local dir tmp i
  local -a values=()
  for i in "${!KEYS[@]}"; do gen_password; values[i]=$PASSWORD; done
  dir=$(dirname "$FILE")
  mkdir -p "$dir"
  tmp=$(umask 077 && mktemp "$dir/.credentials.env.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  {
    echo "# Generated by wazuh_credentials.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Do not commit."
    for i in "${!KEYS[@]}"; do printf '%s=%s\n' "${KEYS[i]}" "${values[i]}"; done
  } >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$FILE"
  trap - EXIT
  report PASS generate "wrote ${#KEYS[@]} passwords to $FILE"
}

case "$MODE" in
  clear)
    if [ -e "$FILE" ]; then rm -f "$FILE"; report PASS clear "removed $FILE"
    else report PASS clear "$FILE does not exist"; fi ;;
  check)
    validate_file || true
    for k in "${KEYS[@]}"; do
      if [[ " ${PRESENT[*]} " == *" $k "* ]]; then report PASS key "$k present"
      else report FAIL key "$k missing"; fi
    done
    report_validation
    if [ -f "$FILE" ]; then report_mode; fi ;;
  force)
    generate
    validate_file || true; report_validation; report_mode ;;
  ensure)
    if [ -e "$FILE" ]; then
      if validate_file; then report PASS exists "$FILE already valid, left untouched"
      else report FAIL exists "$FILE exists but does not validate (fix it, or --force to regenerate)"; fi
      report_validation; report_mode
    else
      generate
      validate_file || true; report_validation; report_mode
    fi ;;
esac
finish
