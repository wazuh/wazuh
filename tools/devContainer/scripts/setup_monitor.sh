#!/bin/bash
# =============================================================================
# setup_monitor.sh – Install dependencies for monitor.py
#
# Creates a Python virtual environment with psutil (required) and optionally
# matplotlib/pandas/numpy (needed only if you also want to run
# monitor_graphics_generator.py on this host).
#
# Supported platforms:
#   - Amazon Linux 2023 (amd64 / aarch64)
#   - Ubuntu 22.04 / 24.04 (amd64 / aarch64)
#   - Debian 11 / 12        (amd64 / aarch64)
#
# This script must be run as root (or with sudo).
# It is idempotent: safe to run multiple times.
#
# Quick start (download from repo and run):
#   curl -fsSL https://raw.githubusercontent.com/wazuh/wazuh/<branch>/src/engine/tools/devContainer/scripts/setup_monitor.sh | bash
#
# To also install charting dependencies (matplotlib, pandas, numpy):
#   INSTALL_CHARTS=1 bash setup_monitor.sh
#
# Default venv location: /opt/wazuh-monitor-venv
# Override:              VENV_DIR=/your/path bash setup_monitor.sh
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via env vars)
# ---------------------------------------------------------------------------
VENV_DIR="${VENV_DIR:-/opt/wazuh-monitor-venv}"
INSTALL_CHARTS="${INSTALL_CHARTS:-0}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { log "ERROR: $*"; exit 1; }
warn() { log "WARN:  $*"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (or with sudo)."
fi

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID}"
    OS_NAME="${PRETTY_NAME:-${ID}}"
else
    die "Cannot detect OS: /etc/os-release not found."
fi

log "Detected OS: ${OS_NAME}"

# ---------------------------------------------------------------------------
# Install Python 3 and venv support
# ---------------------------------------------------------------------------
install_python() {
    case "${OS_ID}" in
        amzn)
            log "Installing Python 3 (dnf)..."
            dnf install -y python3 python3-pip python3-devel gcc gcc-c++ 2>/dev/null || \
                die "dnf install failed"
            ;;
        ubuntu|debian)
            log "Installing Python 3 (apt)..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                python3 python3-pip python3-venv python3-dev gcc g++ 2>/dev/null || \
                die "apt-get install failed"
            ;;
        *)
            # Best-effort: try both package managers
            warn "Unsupported OS '${OS_ID}'. Attempting generic install..."
            if command -v dnf &>/dev/null; then
                dnf install -y python3 python3-pip gcc 2>/dev/null || true
            elif command -v apt-get &>/dev/null; then
                apt-get update -qq && apt-get install -y python3 python3-pip python3-venv gcc 2>/dev/null || true
            fi
            ;;
    esac

    command -v python3 &>/dev/null || die "python3 not available after install attempt."
    log "Python 3 available: $(python3 --version)"
}

# ---------------------------------------------------------------------------
# Create virtual environment
# ---------------------------------------------------------------------------
create_venv() {
    if [[ -d "${VENV_DIR}" && -f "${VENV_DIR}/bin/python3" ]]; then
        log "Virtual environment already exists at ${VENV_DIR}. Skipping creation."
    else
        log "Creating virtual environment at ${VENV_DIR}..."
        python3 -m venv "${VENV_DIR}" || die "Failed to create venv at ${VENV_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Install Python packages inside the venv
# ---------------------------------------------------------------------------
install_packages() {
    local pip="${VENV_DIR}/bin/pip"

    log "Upgrading pip..."
    "${pip}" install --upgrade pip 2>/dev/null || true

    log "Installing psutil (required by monitor.py)..."
    "${pip}" install "psutil>=5.9.0"

    if [[ "${INSTALL_CHARTS}" == "1" ]]; then
        log "Installing charting dependencies (matplotlib, pandas, numpy)..."
        "${pip}" install "matplotlib>=3.5.0" "pandas>=1.4.0" "numpy>=1.22.0"
    fi
}

# ---------------------------------------------------------------------------
# Write a small wrapper so monitor.py can be run directly
# ---------------------------------------------------------------------------
write_wrapper() {
    local wrapper="/usr/local/bin/wazuh-monitor"
    # We can only write a wrapper if monitor.py is co-located; skip when
    # running from a pipe (curl | bash) since $0 is not a real file.
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || return 0
    local monitor_py="${script_dir}/monitor.py"

    if [[ ! -f "${monitor_py}" ]]; then
        log "monitor.py not found next to this script — skipping wrapper creation."
        log "  You can still run: ${VENV_DIR}/bin/python3 /path/to/monitor.py [args]"
        return 0
    fi

    log "Writing convenience wrapper ${wrapper}..."
    cat > "${wrapper}" <<WRAPPER
#!/bin/bash
# Auto-generated by setup_monitor.sh — runs monitor.py inside the wazuh-monitor venv.
exec "${VENV_DIR}/bin/python3" "${monitor_py}" "\$@"
WRAPPER
    chmod +x "${wrapper}"
    log "  Run: wazuh-monitor --help"
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
verify() {
    local errors=0
    log "Verifying installation..."

    local venv_python="${VENV_DIR}/bin/python3"

    if [[ -x "${venv_python}" ]]; then
        log "  [OK] venv python: $(${venv_python} --version) -> ${venv_python}"
    else
        log "  [FAIL] venv python not found at ${venv_python}"; errors=$((errors + 1))
    fi

    if "${venv_python}" -c "import psutil; print(f'  [OK] psutil {psutil.__version__}')" 2>/dev/null; then
        true
    else
        log "  [FAIL] psutil not importable"; errors=$((errors + 1))
    fi

    if [[ "${INSTALL_CHARTS}" == "1" ]]; then
        for pkg in matplotlib pandas numpy; do
            if "${venv_python}" -c "import ${pkg}" 2>/dev/null; then
                log "  [OK] ${pkg}"
            else
                log "  [FAIL] ${pkg} not importable"; errors=$((errors + 1))
            fi
        done
    fi

    if [[ $errors -gt 0 ]]; then
        die "${errors} verification check(s) failed."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "============================================================"
    log "  Wazuh Monitor – Dependency Installer"
    log "  OS:         ${OS_NAME}"
    log "  Venv:       ${VENV_DIR}"
    log "  Charts:     ${INSTALL_CHARTS}"
    log "============================================================"

    install_python
    create_venv
    install_packages
    write_wrapper
    verify

    log ""
    log "============================================================"
    log "  Setup complete!"
    log "  Venv:    ${VENV_DIR}"
    log "  Python:  ${VENV_DIR}/bin/python3"
    log ""
    log "  Run monitor manually:"
    log "    ${VENV_DIR}/bin/python3 monitor.py --output-dir ./out -s 1.0"
    if [[ -f /usr/local/bin/wazuh-monitor ]]; then
        log "  Or via wrapper:"
        log "    wazuh-monitor --output-dir ./out -s 1.0"
    fi
    if [[ "${INSTALL_CHARTS}" != "1" ]]; then
        log ""
        log "  To also install charting deps (for monitor_graphics_generator.py):"
        log "    INSTALL_CHARTS=1 $0"
    fi
    log "============================================================"
}

main "$@"
