#!/usr/bin/env bash

set -euo pipefail

attempts=3
delay=5
backoff=2
max_delay=60
timeout_seconds=""
label=""

usage() {
  cat <<'EOF'
Usage: run_with_retry.sh [options] -- command [args...]

Options:
  --attempts N      Number of attempts. Default: 3
  --delay SECONDS   Initial delay between attempts. Default: 5
  --backoff FACTOR  Delay multiplier after each failure. Default: 2
  --max-delay SEC   Maximum delay between attempts. Default: 60
  --timeout SEC     Timeout applied to each attempt if GNU timeout is available
  --label TEXT      Short label used in retry logs
  -h, --help        Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --attempts)
      attempts="$2"
      shift 2
      ;;
    --delay)
      delay="$2"
      shift 2
      ;;
    --backoff)
      backoff="$2"
      shift 2
      ;;
    --max-delay)
      max_delay="$2"
      shift 2
      ;;
    --timeout)
      timeout_seconds="$2"
      shift 2
      ;;
    --label)
      label="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "[retry] Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "[retry] A command is required." >&2
  usage >&2
  exit 1
fi

use_timeout=false
if [[ -n "$timeout_seconds" ]]; then
  if command -v timeout >/dev/null 2>&1; then
    use_timeout=true
  else
    echo "[retry] GNU timeout is not available. Running without per-attempt timeout." >&2
  fi
fi

current_delay="$delay"
attempt=1

while true; do
  if [[ -n "$label" ]]; then
    echo "[retry] ${label}: attempt ${attempt}/${attempts}" >&2
  else
    echo "[retry] Attempt ${attempt}/${attempts}: $*" >&2
  fi

  set +e
  if $use_timeout; then
    timeout --preserve-status "$timeout_seconds" "$@"
  else
    "$@"
  fi
  exit_code=$?
  set -e

  if [[ $exit_code -eq 0 ]]; then
    exit 0
  fi

  if (( attempt >= attempts )); then
    if [[ -n "$label" ]]; then
      echo "[retry] ${label}: failed after ${attempt} attempts (exit code ${exit_code})." >&2
    else
      echo "[retry] Command failed after ${attempt} attempts (exit code ${exit_code})." >&2
    fi
    exit "$exit_code"
  fi

  echo "[retry] Command failed with exit code ${exit_code}. Retrying in ${current_delay}s." >&2
  sleep "$current_delay"

  attempt=$((attempt + 1))
  next_delay=$((current_delay * backoff))
  if (( next_delay > max_delay )); then
    current_delay="$max_delay"
  else
    current_delay="$next_delay"
  fi
done
