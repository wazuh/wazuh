#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(realpath "$SCRIPT_DIR/../..")"
TEST_FILE="framework/wazuh/core/cluster/dapi/tests/test_dapi.py"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
PYTHONPATH_VALUE="$ROOT_DIR/framework:$ROOT_DIR/api"
LOG_FILE=""
SUPPRESS_WARNINGS=false
MODE="regression"
VERBOSE=false
BOOTSTRAP=false
FORCE_BOOTSTRAP=false
VENV_DIR="$ROOT_DIR/.venv"
REQUIREMENTS_FILE="$ROOT_DIR/framework/requirements-dev.txt"

bootstrap_environment() {
    echo "[*] Bootstrapping Python environment..."

    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 is required to bootstrap environment" >&2
        exit 1
    fi

    if [[ "$FORCE_BOOTSTRAP" == true ]]; then
        echo "[*] Force bootstrap enabled. Recreating .venv"
        rm -rf "$VENV_DIR"
    fi

    if [[ ! -x "$VENV_PYTHON" ]]; then
        echo "[*] Creating venv at $VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi

    echo "[*] Updating pip/setuptools/wheel (compatible versions)"
    "$VENV_PYTHON" -m pip install -U "pip<27" "setuptools<81" "wheel<0.45"

    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
        echo "Error: requirements file not found at $REQUIREMENTS_FILE" >&2
        exit 1
    fi

     if [[ "$FORCE_BOOTSTRAP" == true ]] || \
         ! "$VENV_PYTHON" -m pip show pytest >/dev/null 2>&1 || \
         ! "$VENV_PYTHON" -c "import pkg_resources" >/dev/null 2>&1; then
        echo "[*] Installing requirements from framework/requirements-dev.txt"
        "$VENV_PYTHON" -m pip install "Cython==0.29.36" "wheel<0.45" "setuptools<70"
        "$VENV_PYTHON" -m pip install --no-build-isolation "PyYAML==5.4.1"
        "$VENV_PYTHON" -m pip install -r "$REQUIREMENTS_FILE"
    else
        echo "[*] Dependencies already installed (pytest found). Skipping reinstall"
    fi
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --regression           Run only new regression tests (default)
  --full                 Run full DAPI test file
    --verbose              Show each test and detailed summary (-vv -rA)
    --bootstrap            Create/update .venv and install test dependencies before running
    --force-bootstrap      Recreate .venv and reinstall dependencies from scratch
  --no-warnings          Suppress deprecation warnings in output
  --log FILE             Save output to FILE (and print to console)
  --help                 Show this help

Examples:
  $(basename "$0") --regression
  $(basename "$0") --full --no-warnings
    $(basename "$0") --full --verbose --log /tmp/pytest_dapi_full_verbose.log
    $(basename "$0") --bootstrap --regression
    $(basename "$0") --force-bootstrap --full
  $(basename "$0") --regression --log /tmp/pytest_regression.log
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regression)
            MODE="regression"
            ;;
        --full)
            MODE="full"
            ;;
        --no-warnings)
            SUPPRESS_WARNINGS=true
            ;;
        --verbose)
            VERBOSE=true
            ;;
        --bootstrap)
            BOOTSTRAP=true
            ;;
        --force-bootstrap)
            BOOTSTRAP=true
            FORCE_BOOTSTRAP=true
            ;;
        --log)
            shift
            if [[ $# -eq 0 ]]; then
                echo "Error: --log requires a file path" >&2
                exit 1
            fi
            LOG_FILE="$1"
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
done

if [[ "$BOOTSTRAP" == true ]] || [[ ! -x "$VENV_PYTHON" ]]; then
    bootstrap_environment
fi

PYTEST_ARGS=("$TEST_FILE")

if [[ "$VERBOSE" == true ]]; then
    PYTEST_ARGS=("-vv" "-rfE" "${PYTEST_ARGS[@]}")
else
    PYTEST_ARGS=("-q" "${PYTEST_ARGS[@]}")
fi

if [[ "$MODE" == "regression" ]]; then
    PYTEST_ARGS+=("-k" "dapi_object_hook or recalculates_rbac_permissions")
fi

if [[ "$SUPPRESS_WARNINGS" == true ]]; then
    PYTEST_ARGS+=("-W" "ignore::DeprecationWarning" "-W" "ignore::PendingDeprecationWarning")
fi

echo "[*] Root directory: $ROOT_DIR"
echo "[*] Mode: $MODE"
echo "[*] Running: $VENV_PYTHON -m pytest ${PYTEST_ARGS[*]}"

if [[ -n "$LOG_FILE" ]]; then
    mkdir -p "$(dirname "$LOG_FILE")"
    (
        cd "$ROOT_DIR"
        set -o pipefail
        PYTHONPATH="$PYTHONPATH_VALUE" "$VENV_PYTHON" -m pytest "${PYTEST_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
    )
    status=$?
    echo "[*] Log saved to: $LOG_FILE"
else
    (
        cd "$ROOT_DIR"
        PYTHONPATH="$PYTHONPATH_VALUE" "$VENV_PYTHON" -m pytest "${PYTEST_ARGS[@]}"
    )
    status=$?
fi

echo "[*] Exit code: $status"
exit $status
