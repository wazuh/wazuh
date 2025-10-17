#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Project local virtualenv bootstrapper & layered installs
#
# This script:
#   1) Creates a clean Python virtual environment under build/venv
#   2) Upgrades pip/setuptools/wheel
#   3) Installs a set of local packages in a fixed order
#
# Usage:
#   ./bootstrap.sh
#
# Common variants:
#   EDITABLE=1 ./bootstrap.sh      # install local packages in editable mode
#
# Exit codes:
#   - Non-zero on any failure (set -e) to make CI and developers fail fast.
#
# Notes:
#   - The install order is intentional due to inter-package dependencies.
#   - api-communication is installed without --no-deps so that missing
#     external dependencies can be resolved automatically if needed.
#   - All other local packages default to --no-deps and --no-build-isolation
#     to keep installs fast and deterministic when developing locally.
# ------------------------------------------------------------------------------

set -euo pipefail

# --- Configuration ------------------------------------------------------------

# Base directory to resolve local package paths.
# Defaults to the current working directory so you can run the script from repo root.
BASE="${BASE:-$PWD}"

# Virtual environment location (deleted and recreated on each run).
VENV_DIR="${VENV_DIR:-build/venv}"

# Editable mode:
#   1 -> install local packages with `pip install -e` (symlinked sources)
#   0 -> install as regular builds (used for packaging/CI)
EDITABLE="${EDITABLE:-0}"  # 1 in local dev, 0 when packaging

# --- Bootstrap virtual environment --------------------------------------------

# Start from a clean environment to avoid stale wheels / metadata.
rm -rf "$VENV_DIR"

# Create virtualenv
python3 -m venv "$VENV_DIR"

# Activate it for the remainder of the script
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"

# Ensure modern packaging tooling
python -m pip install --upgrade pip wheel setuptools
python -m pip install PyYAML
python -m pip install lxml
python -m pip install docker
python -m pip install requests
python -m pip install graphviz

# --- Helper: install a local package if pyproject/setup is present -------------
# Arguments:
#   $1 -> path to the local package directory
#   $2 -> human-friendly label for logs
#   $3 -> (optional) additional pip flags (defaults to: --no-deps --no-build-isolation)
install_local () {
  local path="${1:?missing path}"
  local label="${2:?missing label}"
  local flags="${3:---no-deps --no-build-isolation}"

  if [ -d "$path" ]; then
    if [ -f "$path/pyproject.toml" ] || [ -f "$path/setup.py" ]; then
      echo "[i] Installing ${label} from ${path} (flags: ${flags}) editable=${EDITABLE}"
      if [ "${EDITABLE}" = "1" ]; then
        # Editable install for live code changes (development convenience).
        # shellcheck disable=SC2086
        python -m pip install -e "$path" $flags
      else
        # Regular install for packaging/CI.
        # shellcheck disable=SC2086
        python -m pip install "$path" $flags
      fi
    else
      echo "[!] ${label}: no pyproject.toml or setup.py in ${path} — skipping"
    fi
  else
    echo "[!] ${label}: path does not exist: ${path} — skipping"
  fi
}

# --- Installation order (intentionally fixed) ---------------------------------
# 1) api-communication
#    Install WITHOUT --no-deps so it can pull external deps if the environment lacks them.
install_local "$BASE/tools/api-communication" "api-communication" "--no-build-isolation"

# 2) engine-suite
install_local "$BASE/tools/engine-suite" "engine-suite"

# 3) engine-test-utils
install_local "$BASE/test/engine-test-utils" "engine-test-utils"

# 4) health_test
install_local "$BASE/test/health_test/engine-health-test" "health_test"

# 5) helper_tests
install_local "$BASE/test/helper_tests/engine-helper-test" "helper_tests"

# 6) integration_tests
install_local "$BASE/test/integration_tests/engine-it" "integration_tests"

echo "[i] Environment is ready at: ${VENV_DIR}"
echo "[i] Activate it with: source ${VENV_DIR}/bin/activate"
