#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEFAULT_PYTHON_CANDIDATES=(
  "/var/ossec/framework/python/bin/python3"
  "$WORKSPACE_ROOT/.venv/bin/python"
  "$WORKSPACE_ROOT/.venv/bin/python3"
  "$WORKSPACE_ROOT/framework/.venv/bin/python"
  "$WORKSPACE_ROOT/framework/.venv/bin/python3"
  "/usr/bin/python3"
)

DEFAULT_CLUSTER_CONTROL_CANDIDATES=(
  "/var/ossec/framework/scripts/cluster_control.py"
  "$WORKSPACE_ROOT/framework/scripts/cluster_control.py"
)

PYTHON_BIN="${PYTHON_BIN:-}"
CLUSTER_CONTROL_SCRIPT="${CLUSTER_CONTROL_SCRIPT:-}"
USE_REPO_PYTHONPATH=0

SYSTEM_WAZUH_PYTHON="/var/ossec/framework/python/bin/python3"
SYSTEM_CLUSTER_CONTROL="/var/ossec/framework/scripts/cluster_control.py"

usage() {
  cat <<'EOF'
Usage:
  ./tools/testing/check_cluster.sh [--list-only | --health-only]

Options:
  --list-only    Show cluster node list only.
  --health-only  Show detailed cluster health only.
  -h, --help     Show this help.

Default behavior (no options): run both checks in order.

Optional environment overrides:
  PYTHON_BIN=/path/to/python3
  CLUSTER_CONTROL_SCRIPT=/path/to/cluster_control.py
EOF
}

pick_first_executable() {
  local candidate
  for candidate in "$@"; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

pick_first_file() {
  local candidate
  for candidate in "$@"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

prepare_pythonpath_if_repo_script() {
  if [[ "$CLUSTER_CONTROL_SCRIPT" == "$WORKSPACE_ROOT/framework/scripts/cluster_control.py" ]]; then
    USE_REPO_PYTHONPATH=1
    local repo_pythonpath="$WORKSPACE_ROOT/framework:$WORKSPACE_ROOT/api"
    if [[ -n "${PYTHONPATH:-}" ]]; then
      export PYTHONPATH="$repo_pythonpath:$PYTHONPATH"
    else
      export PYTHONPATH="$repo_pythonpath"
    fi
  fi
}

can_import_wazuh() {
  local py_bin="$1"
  local script_path="$2"
  local base_pythonpath="${PYTHONPATH:-}"
  local test_pythonpath="$base_pythonpath"

  if [[ "$script_path" == "$WORKSPACE_ROOT/framework/scripts/cluster_control.py" ]]; then
    local repo_pythonpath="$WORKSPACE_ROOT/framework:$WORKSPACE_ROOT/api"
    if [[ -n "$test_pythonpath" ]]; then
      test_pythonpath="$repo_pythonpath:$test_pythonpath"
    else
      test_pythonpath="$repo_pythonpath"
    fi
  fi

  PYTHONPATH="$test_pythonpath" "$py_bin" -c "import wazuh.core.cluster.cluster" >/dev/null 2>&1
}

auto_select_runtime_pair() {
  local py_candidate
  local script_candidate

  for py_candidate in "${DEFAULT_PYTHON_CANDIDATES[@]}"; do
    [[ -x "$py_candidate" ]] || continue
    for script_candidate in "${DEFAULT_CLUSTER_CONTROL_CANDIDATES[@]}"; do
      [[ -f "$script_candidate" ]] || continue
      if can_import_wazuh "$py_candidate" "$script_candidate"; then
        PYTHON_BIN="$py_candidate"
        CLUSTER_CONTROL_SCRIPT="$script_candidate"
        return 0
      fi
    done
  done

  return 1
}

prefer_system_wazuh_runtime_if_available() {
  if [[ -z "${PYTHON_BIN:-}" && -z "${CLUSTER_CONTROL_SCRIPT:-}" ]]; then
    if sudo test -x "$SYSTEM_WAZUH_PYTHON" && sudo test -f "$SYSTEM_CLUSTER_CONTROL"; then
      PYTHON_BIN="$SYSTEM_WAZUH_PYTHON"
      CLUSTER_CONTROL_SCRIPT="$SYSTEM_CLUSTER_CONTROL"
      return 0
    fi
  fi

  return 1
}

run_list() {
  echo "==> Cluster nodes"
  sudo env "PYTHONPATH=${PYTHONPATH:-}" "$PYTHON_BIN" "$CLUSTER_CONTROL_SCRIPT" -l
}

run_health() {
  echo
  echo "==> Cluster health (detailed)"
  sudo env "PYTHONPATH=${PYTHONPATH:-}" "$PYTHON_BIN" "$CLUSTER_CONTROL_SCRIPT" -i more
}

if [[ -z "$PYTHON_BIN" ]]; then
  prefer_system_wazuh_runtime_if_available || true
fi

if [[ -z "$PYTHON_BIN" ]]; then
  if ! PYTHON_BIN="$(pick_first_executable "${DEFAULT_PYTHON_CANDIDATES[@]}")"; then
    echo "Error: Python runtime not found. Set PYTHON_BIN to a valid python3 executable." >&2
    exit 1
  fi
elif [[ ! -x "$PYTHON_BIN" ]]; then
  if [[ "$PYTHON_BIN" == /var/ossec/* ]]; then
    if ! sudo test -x "$PYTHON_BIN"; then
      echo "Error: PYTHON_BIN is not executable (even with sudo): $PYTHON_BIN" >&2
      exit 1
    fi
  else
    echo "Error: PYTHON_BIN is not executable: $PYTHON_BIN" >&2
    exit 1
  fi
fi

if [[ -z "$CLUSTER_CONTROL_SCRIPT" ]]; then
  prefer_system_wazuh_runtime_if_available || true
fi

if [[ -z "$CLUSTER_CONTROL_SCRIPT" ]]; then
  if ! CLUSTER_CONTROL_SCRIPT="$(pick_first_file "${DEFAULT_CLUSTER_CONTROL_CANDIDATES[@]}")"; then
    echo "Error: cluster_control.py not found. Set CLUSTER_CONTROL_SCRIPT with the full path." >&2
    exit 1
  fi
elif [[ ! -f "$CLUSTER_CONTROL_SCRIPT" ]]; then
  if [[ "$CLUSTER_CONTROL_SCRIPT" == /var/ossec/* ]]; then
    if ! sudo test -f "$CLUSTER_CONTROL_SCRIPT"; then
      echo "Error: CLUSTER_CONTROL_SCRIPT not found (even with sudo): $CLUSTER_CONTROL_SCRIPT" >&2
      exit 1
    fi
  else
    echo "Error: CLUSTER_CONTROL_SCRIPT not found: $CLUSTER_CONTROL_SCRIPT" >&2
    exit 1
  fi
fi

if [[ -z "${PYTHON_BIN:-}" || -z "${CLUSTER_CONTROL_SCRIPT:-}" ]]; then
  if ! auto_select_runtime_pair; then
    echo "Error: Could not find a compatible Python + cluster_control.py pair with wazuh module available." >&2
    echo "Set both PYTHON_BIN and CLUSTER_CONTROL_SCRIPT manually." >&2
    exit 1
  fi
fi

if [[ "$PYTHON_BIN" != "$SYSTEM_WAZUH_PYTHON" || "$CLUSTER_CONTROL_SCRIPT" != "$SYSTEM_CLUSTER_CONTROL" ]]; then
  if ! can_import_wazuh "$PYTHON_BIN" "$CLUSTER_CONTROL_SCRIPT"; then
    if ! auto_select_runtime_pair; then
      echo "Error: Selected runtime cannot import wazuh." >&2
      echo "Current PYTHON_BIN=$PYTHON_BIN" >&2
      echo "Current CLUSTER_CONTROL_SCRIPT=$CLUSTER_CONTROL_SCRIPT" >&2
      exit 1
    fi
  fi
fi

if [[ "$PYTHON_BIN" == "$SYSTEM_WAZUH_PYTHON" && "$CLUSTER_CONTROL_SCRIPT" == "$SYSTEM_CLUSTER_CONTROL" ]]; then
  USE_REPO_PYTHONPATH=0
else
  if ! can_import_wazuh "$PYTHON_BIN" "$CLUSTER_CONTROL_SCRIPT"; then
    if ! auto_select_runtime_pair; then
      echo "Error: Selected runtime cannot import wazuh." >&2
      echo "Current PYTHON_BIN=$PYTHON_BIN" >&2
      echo "Current CLUSTER_CONTROL_SCRIPT=$CLUSTER_CONTROL_SCRIPT" >&2
      exit 1
    fi
  fi
fi

prepare_pythonpath_if_repo_script

echo "Using Python: $PYTHON_BIN"
echo "Using script: $CLUSTER_CONTROL_SCRIPT"

mode="both"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --list-only)
      mode="list"
      ;;
    --health-only)
      mode="health"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
fi

case "$mode" in
  list)
    run_list
    ;;
  health)
    run_health
    ;;
  both)
    run_list
    run_health
    ;;
esac
