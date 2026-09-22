#!/usr/bin/env bash
# wazuh_install_manager.sh — fresh, unattended install of the wazuh-manager from THIS checkout, with
# the evidence a PR needs: provenance of what was installed (and of what was there before), the
# install/start logs, the certificates, and a parseable verification (wazuh_verify_manager.sh).
#
# DESTRUCTIVE: mode fresh stops and PURGES the manager at --dir (default /var/wazuh-manager) with
# tools/purge_wazuh.sh; mode sandbox removes --dir. It refuses to run without --yes.
#
# Steps (each one is marked "=== <step> <ISO-8601>" in --out/install.log):
#   0. provenance of the installed manager (etc/.install-provenance) and, with --before-hook, that
#      script run against it — the "before" of a before/after comparison; --snapshot tars bin/ lib/
#   1. build-tree guard: src/build must not carry UNIT_TEST / ENGINE_ENABLE_*SAN / ENGINE_BUILD_TEST
#      (an ASAN engine installs fine and then fails with a misleading libwazuhshared.so dlopen error)
#   2. stop + purge (fresh) or rm -rf of the sandbox dir (sandbox; never an existing dir — D44)
#   3. ./install.sh unattended (USER_* variables, stdin from /dev/null; binary-install with --skip-build)
#   4. lib/libwazuhshared.so copied by hand when install.sh did not (inst-functions.sh only copies it
#      from build/lib at that relative path)
#   5. certificates: the manager generates none; e2e/init.sh --certs-only (reusing certs/ and its CA)
#      + wazuh_copy_certs.sh; init.sh also opens the remoted listeners to 0.0.0.0 for docker agents
#   6. etc/.install-provenance written; start.mark = byte offset of the log before `start`
#   7. wazuh-manager-control start, output to a FILE (never a pipe: the daemons inherit it)
#   8. wazuh_verify_manager.sh, then --before-hook again as the "after"
#   9. --out/manifest.md
#
# Used by the VS Code task "E2E Scripts: [Manager] Fresh install from branch (purge!)" and by the
# manager-env skill (which asks the user before running it).
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR="${WAZUH_REPO:-$(cd "$SCRIPT_DIR/../../../../.." && pwd)}"   # e2e → devContainer → tools → engine → src → repo

usage() {
  cat <<EOF
Usage: sudo $0 --yes [--mode fresh|sandbox] [--dir DIR] [--out DIR] [--before-hook SCRIPT]
                     [--snapshot] [--skip-build] [--no-start] [--api]
                     [--https-port N] [--legacy-port N] [-h|--help]

  --yes               required: acknowledges that --dir will be purged (fresh) or removed (sandbox)
  --mode fresh        purge + install into --dir (default /var/wazuh-manager), system service registered
  --mode sandbox      install into --dir (default \$TMP_CLEAN_ENV/wazuh-manager) with USER_REGISTER_SERVICE=n;
                      the basename MUST be wazuh-manager; the dir must NOT exist (reinstalling into an
                      existing sandbox wipes the registered manager's framework/ — D44)
  --dir DIR           installation directory (see --mode)
  --out DIR           evidence directory (default \$TMPDIR/wazuh-e2e-evidence/<timestamp>)
  --before-hook S     script run with WAZUH_MANAGER_HOME=DIR against the installed manager BEFORE the
                      purge (before-hook.log) and again after the new start (after-hook.log)
  --snapshot          tar bin/ lib/ of the previous install into --out/snapshot-before.tar
  --skip-build        pass binary-install to install.sh (use the binaries already in src/build)
  --no-start          stop after the install (no start, no verification)
  --api               make wazuh_verify_manager.sh also try the API login
  --https-port N      sandbox only: WAZUH_REMOTE_HTTPS_PORT for install.sh (default 1517)
  --legacy-port N     sandbox only: WAZUH_REMOTE_LEGACY_PORT for install.sh (default 1514)

Repository: $REPO_DIR (override with WAZUH_REPO)
EOF
}

YES=0; MODE=fresh; DIR=""; OUT=""; HOOK=""; SNAPSHOT=0; SKIP_BUILD=0; NO_START=0; API=0
HTTPS_PORT=""; LEGACY_PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1; shift ;;
    --mode) MODE=$2; shift 2 ;;
    --dir) DIR=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --before-hook) HOOK=$2; shift 2 ;;
    --snapshot) SNAPSHOT=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --api) API=1; shift ;;
    --https-port) HTTPS_PORT=$2; shift 2 ;;
    --legacy-port) LEGACY_PORT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

[ "$YES" -eq 1 ] || { usage >&2; die "--yes is required: this script purges or removes the installation at --dir"; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
case "$MODE" in
  fresh)   DIR="${DIR:-/var/wazuh-manager}" ;;
  sandbox) DIR="${DIR:-${TMP_CLEAN_ENV:-/tmp/clean_env}/wazuh-manager}"
           [ "$(basename "$DIR")" = "wazuh-manager" ] || die "sandbox basename must be wazuh-manager (the QA framework selects the control script by it)"
           [ "$DIR" != "/var/wazuh-manager" ] || die "sandbox mode cannot target /var/wazuh-manager (use --mode fresh)" ;;
  *) die "unknown --mode $MODE" ;;
esac
[ -f "$REPO_DIR/install.sh" ] || die "no install.sh in $REPO_DIR (set WAZUH_REPO)"
[ -z "$HOOK" ] || [ -x "$HOOK" ] || die "--before-hook $HOOK is not executable"

OUT="${OUT:-${TMPDIR:-/tmp}/wazuh-e2e-evidence/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
LOG="$OUT/install.log"
: > "$LOG"
log()  { echo "$*" | tee -a "$LOG"; }
step() { log "=== $1 $(now)"; }

CTRL="$DIR/bin/wazuh-manager-control"
CONF="$DIR/bin/wazuh-manager-conf"
LOGF="$DIR/logs/wazuh-manager.log"
E2E="$SCRIPT_DIR"

HEAD=$(git -C "$REPO_DIR" rev-parse --short=10 HEAD 2>/dev/null || echo unknown)
BRANCH=$(git -C "$REPO_DIR" branch --show-current 2>/dev/null || echo unknown)
BASE=$(command -v gh >/dev/null 2>&1 && (cd "$REPO_DIR" && gh pr view --json baseRefName -q .baseRefName 2>/dev/null) || true)
BASE="${BASE:-${BASE_BRANCH:-5.0.0}}"
MERGE_BASE=$(git -C "$REPO_DIR" merge-base HEAD "origin/$BASE" 2>/dev/null | cut -c1-10 || echo unknown)
MERGE_BASE="${MERGE_BASE:-unknown}"

log "# wazuh_install_manager.sh — $(now) — mode=$MODE dir=$DIR repo=$REPO_DIR"
log "# branch=$BRANCH head=$HEAD base=origin/$BASE merge_base=$MERGE_BASE out=$OUT"

# ---------------------------------------------------------------- 0. the "before"
step "before"
BEFORE_PROV="none (no manager at $DIR)"
if [ -x "$CTRL" ]; then
  if [ -f "$DIR/etc/.install-provenance" ]; then
    BEFORE_PROV=$(tr '\n' ' ' < "$DIR/etc/.install-provenance")
  else
    BEFORE_PROV="head=unknown installed=$(stat -c %y "$DIR/bin/wazuh-manager-remoted" 2>/dev/null | cut -d. -f1 | tr ' ' T) (no .install-provenance; NOT necessarily the merge-base)"
  fi
  log "before.provenance: $BEFORE_PROV"
  if [ -n "$HOOK" ]; then
    log "before-hook: $HOOK"
    WAZUH_MANAGER_HOME="$DIR" "$HOOK" > "$OUT/before-hook.log" 2>&1
    log "before-hook rc=$? → $OUT/before-hook.log"
  fi
  if [ "$SNAPSHOT" -eq 1 ]; then
    tar -C "$DIR" -cf "$OUT/snapshot-before.tar" bin lib 2>>"$LOG" && log "snapshot: $OUT/snapshot-before.tar ($(du -h "$OUT/snapshot-before.tar" | cut -f1))"
  fi
else
  log "before.provenance: $BEFORE_PROV"
fi

# ---------------------------------------------------------------- 1. build-tree guard
step "build-tree-guard"
CACHE="$REPO_DIR/src/build/CMakeCache.txt"
if [ -f "$CACHE" ]; then
  bad=$(grep -E '^(ENGINE_ENABLE_(A|T|UB)SAN|ENGINE_BUILD_TEST|UNIT_TEST):BOOL=ON' "$CACHE" || true)
  if [ -n "$bad" ]; then
    log "$bad"
    die "src/build is a test/sanitizer tree; reconfigure first: cmake -S $REPO_DIR/src -B $REPO_DIR/src/build -DTARGET=manager -DUNIT_TEST=OFF -DENGINE_ENABLE_ASAN=OFF -DENGINE_BUILD_TEST=OFF && cmake --build $REPO_DIR/src/build -j"
  fi
  if [ -x "$REPO_DIR/src/build/engine/wazuh-engine" ]; then
    asan=$(ldd "$REPO_DIR/src/build/engine/wazuh-engine" 2>/dev/null | grep -c asan || true)
    [ "$asan" -eq 0 ] || die "src/build/engine/wazuh-engine links libasan ($asan): rebuild it plain before installing"
  fi
  log "src/build: plain (no UNIT_TEST / sanitizer / ENGINE_BUILD_TEST cached)"
else
  log "WARNING: no $CACHE — install.sh will configure and build the whole tree (slow)"
  [ "$SKIP_BUILD" -eq 0 ] || die "--skip-build needs an already built src/build"
fi

# ---------------------------------------------------------------- 2. stop + purge / remove
step "purge"
if [ "$MODE" = fresh ]; then
  [ -x "$CTRL" ] && { "$CTRL" stop >>"$LOG" 2>&1 || true; }
  [ -x "$REPO_DIR/tools/purge_wazuh.sh" ] || die "tools/purge_wazuh.sh missing"
  "$REPO_DIR/tools/purge_wazuh.sh" >>"$LOG" 2>&1
  log "purge rc=$?"
else
  if [ -d "$DIR" ]; then
    [ -x "$CTRL" ] && { "$CTRL" stop >>"$LOG" 2>&1 || true; }
    rm -rf "$DIR"   # a fresh dir never takes install.sh's UpdateStopWAZUH path (D44)
    log "removed previous sandbox $DIR"
  fi
fi

# ---------------------------------------------------------------- 3. install.sh
step "install"
# install.sh refuses a manager that does not name the indexer user's password. The devcontainer has no
# indexer, so the value only has to exist.
declare -a ENVV=(USER_LANGUAGE=en USER_NO_STOP=y USER_INSTALL_TYPE=manager "USER_DIR=$DIR"
                 USER_DELETE_DIR=y USER_ENABLE_AUTHD=y USER_AUTO_START=n
                 "INDEXER_USER_PASSWORD=${INDEXER_USER_PASSWORD:-DevCont4iner-Indexer.}")
if [ "$MODE" = sandbox ]; then
  ENVV+=(USER_REGISTER_SERVICE=n USER_CLEANINSTALL=y)
  [ -z "$HTTPS_PORT" ] || ENVV+=("WAZUH_REMOTE_HTTPS_PORT=$HTTPS_PORT")
  [ -z "$LEGACY_PORT" ] || ENVV+=("WAZUH_REMOTE_LEGACY_PORT=$LEGACY_PORT")
fi
declare -a INSTALL_ARGS=()
[ "$SKIP_BUILD" -eq 0 ] || INSTALL_ARGS+=(binary-install)
( cd "$REPO_DIR" && env "${ENVV[@]}" ./install.sh "${INSTALL_ARGS[@]}" < /dev/null ) >>"$LOG" 2>&1
rc=$?
log "install rc=$rc"
[ "$rc" -eq 0 ] || die "install.sh failed (rc=$rc), see $LOG"
warnings=$(grep -c 'warning:' "$LOG" || true)
asan_syms=$(ldd "$DIR/bin/wazuh-manager-analysisd" 2>/dev/null | grep -c asan || true)
{ echo "# build output is in install.log (install.sh builds the tree unless binary-install)"
  echo "warnings=$warnings"; echo "asan_syms=$asan_syms"; } > "$OUT/build.log"
log "build: warnings=$warnings asan_syms=$asan_syms"

# ---------------------------------------------------------------- 4. libwazuhshared
step "libwazuhshared"
if [ ! -f "$DIR/lib/libwazuhshared.so" ] && [ -f "$REPO_DIR/src/build/lib/libwazuhshared.so" ]; then
  install -m 0750 -o root -g wazuh-manager "$REPO_DIR/src/build/lib/libwazuhshared.so" "$DIR/lib/"
  log "copied src/build/lib/libwazuhshared.so by hand"
fi
ls -l "$DIR/lib/libwazuhshared.so" >>"$LOG" 2>&1 || die "lib/libwazuhshared.so missing after install"

# ---------------------------------------------------------------- 5. certificates
step "certificates"
if [ -f "$E2E/certs/root-ca.pem" ] && [ -f "$E2E/certs/root-ca.key" ]; then
  log "reusing $E2E/certs (CA kept; pass --rotate-ca to init.sh yourself to rotate it)"
  WAZUH_MANAGER_HOME="$DIR" "$E2E/init.sh" --certs-only --reuse-certs >>"$LOG" 2>&1 || die "init.sh --certs-only failed"
else
  WAZUH_MANAGER_HOME="$DIR" "$E2E/init.sh" --certs-only --regen-certs >>"$LOG" 2>&1 || die "init.sh --certs-only --regen-certs failed"
fi
WAZUH_MANAGER_HOME="$DIR" "$E2E/wazuh_copy_certs.sh" >>"$LOG" 2>&1 || die "wazuh_copy_certs.sh failed"
certs_line=$(openssl x509 -in "$DIR/etc/certs/remoted.pem" -noout -subject -issuer -enddate 2>/dev/null | tr '\n' ' ')
log "remoted.pem: $certs_line"

# ---------------------------------------------------------------- 6. provenance + start mark
step "provenance"
PROV="$DIR/etc/.install-provenance"
{
  echo "head=$HEAD"; echo "branch=$BRANCH"; echo "merge_base=$MERGE_BASE"; echo "base=origin/$BASE"
  echo "date=$(now)"; echo "mode=$MODE"; echo "installer=wazuh_install_manager.sh"; echo "build_tree=src/build"
  echo "skip_build=$SKIP_BUILD"
  for f in bin/wazuh-manager-remoted bin/wazuh-manager-analysisd bin/wazuh-manager-authd bin/wazuh-manager-db \
           bin/wazuh-manager-modulesd lib/libremoted_module.so lib/libwazuhshared.so; do
    [ -f "$DIR/$f" ] && echo "sha256.$f=$(sha256sum "$DIR/$f" | cut -d' ' -f1)"
  done
} > "$PROV"
chown root:wazuh-manager "$PROV"; chmod 640 "$PROV"
{
  cat "$PROV"
  echo "before.provenance=$BEFORE_PROV"
  "$CONF" get remote 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin); h=d.get("https",{}); l=d.get("legacy",{})
print("https.port=%s"%h.get("port")); print("https.bind_addr=%s"%h.get("bind_addr")); print("https.global_prefix=%s"%h.get("global_prefix"))
print("legacy.port=%s"%l.get("port")); print("legacy.local_ip=%s"%l.get("local_ip"))' 2>/dev/null || echo "remote.config=unreadable"
} > "$OUT/provenance.txt"
cat "$OUT/provenance.txt" >>"$LOG"

if [ "$NO_START" -eq 1 ]; then
  step "done (--no-start)"
  exit 0
fi

# ---------------------------------------------------------------- 7. start (to a file, never a pipe)
step "start"
mark=$( [ -f "$LOGF" ] && wc -c < "$LOGF" || echo 0 )
echo "$mark" > "$OUT/start.mark"
START_T=$(now)
"$CTRL" start > "$OUT/start.log" 2>&1
rc=$?
log "start rc=$rc at $START_T (mark=$mark) → $OUT/start.log"

# ---------------------------------------------------------------- 8. verify + after hook
step "verify"
declare -a VARGS=(--home "$DIR" --out "$OUT" --start-mark "$OUT/start.mark" --no-manifest)
[ "$API" -eq 0 ] || VARGS+=(--api)
"$E2E/wazuh_verify_manager.sh" "${VARGS[@]}" | tee -a "$LOG"
verify_rc=${PIPESTATUS[0]}
if [ -n "$HOOK" ]; then
  log "after-hook: $HOOK"
  WAZUH_MANAGER_HOME="$DIR" "$HOOK" > "$OUT/after-hook.log" 2>&1
  log "after-hook rc=$? → $OUT/after-hook.log"
fi

# ---------------------------------------------------------------- 9. manifest
step "manifest"
summary=$(grep -E '^# summary:' "$OUT/verify-manager.log" | tail -1 | sed 's/^# //')
{
  echo "# manager-env manifest — $(now)"
  echo "mode: $MODE"
  echo "repo.head: $HEAD   repo.branch: $BRANCH   repo.merge_base: $MERGE_BASE (origin/$BASE)"
  echo "manager.home: $DIR"
  echo "before.provenance: $BEFORE_PROV"
  [ -n "$HOOK" ] && echo "before.hook: before-hook.log   after.hook: after-hook.log ($HOOK)"
  echo "install.rc: 0   install.log: install.log   build: warnings=$warnings asan_syms=$asan_syms"
  grep -E '^sha256\.' "$PROV" | sed 's/^/binaries./'
  echo "certs.remoted: $certs_line   certs.ca_reused: $([ -f "$E2E/certs/root-ca.key" ] && echo yes || echo no)"
  echo "start.time: $START_T   start.mark: $mark   start.log: start.log"
  echo
  echo "| # | check | verdict | got / reason |"
  echo "|---|---|---|---|"
  awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4 }' "$OUT/checks.tsv"
  echo
  echo "$summary"
  echo "logs: install.log build.log provenance.txt start.log verify-manager.log checks.tsv status.txt conf-validate.txt cacerts.pem manager.log manager-errors.log$( [ -n "$HOOK" ] && echo ' before-hook.log after-hook.log')"
} > "$OUT/manifest.md"
log "# manifest: $OUT/manifest.md"
step "done"
exit "$verify_rc"
