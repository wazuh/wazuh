#!/bin/bash
# =============================================================================
# setup_dependencies.sh – Install all dependencies for acceptance_test.sh
#
# Supported platforms:
#   - Amazon Linux 2023 (amd64 / aarch64)
#   - Ubuntu 24.04      (amd64 / aarch64)
#
# This script must be run as root (or with sudo).
# It is idempotent: safe to run multiple times.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Go version to install (update as needed)
# ---------------------------------------------------------------------------
GO_VERSION="${GO_VERSION:-1.23.6}"

# ---------------------------------------------------------------------------
# Python virtual-environment directory (override with VENV_DIR env var)
# ---------------------------------------------------------------------------
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-${_SELF_DIR}/.venv}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (or with sudo)."
fi

# ---------------------------------------------------------------------------
# Detect OS and architecture
# ---------------------------------------------------------------------------
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-${ID}}"
    else
        die "Cannot detect OS: /etc/os-release not found."
    fi
}

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "${machine}" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       die "Unsupported architecture: ${machine}" ;;
    esac
    log "Architecture: ${machine} -> Go arch: ${ARCH}"
}

detect_os
detect_arch

log "Detected OS: ${OS_NAME} (${OS_ID} ${OS_VERSION})"

# ---------------------------------------------------------------------------
# Package manager abstraction
# ---------------------------------------------------------------------------
install_system_packages() {
    case "${OS_ID}" in
        amzn)
log "Using dnf (Amazon Linux)..."

            dnf upgrade -y

            # Base packages (including curl) are minimal in Amazon Linux 2023, so we explicitly list them.
            local packages=(
                python3
                python3-pip
                python3-devel
                procps-ng
                dmidecode
                util-linux
                tar
                gzip
                gcc
                gcc-c++
                findutils
                grep
                coreutils
            )

            dnf install -y "${packages[@]}"

            # Same as above, but ensure we have the full curl package (not the minimal one) for better TLS support and features.
            if ! command -v curl &>/dev/null; then
                log "curl not found, installing curl-full (replacing minimal)..."
                dnf swap -y curl-minimal curl-full || \
                dnf install -y curl --allowerasing
            else
                log "curl already available (likely curl-minimal), skipping install."
            fi
            ;;
        ubuntu|debian)
            log "Using apt (Ubuntu/Debian)..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                python3 \
                python3-pip \
                python3-venv \
                python3-dev \
                curl \
                procps \
                dmidecode \
                util-linux \
                tar \
                gzip \
                gcc \
                g++ \
                findutils \
                grep \
                coreutils \
                unzip
            ;;
        *)
            die "Unsupported OS: ${OS_ID}. Supported: amzn (Amazon Linux 2023), ubuntu."
            ;;
    esac
    log "System packages installed."
}

# ---------------------------------------------------------------------------
# Install Go (from official tarball)
# ---------------------------------------------------------------------------
install_go() {
    # Check if Go is already installed and matches the desired version
    if command -v go &>/dev/null; then
        local current_version
        current_version="$(go version | grep -oP 'go\K[0-9]+\.[0-9]+(\.[0-9]+)?')"
        if [[ "${current_version}" == "${GO_VERSION}" ]]; then
            log "Go ${GO_VERSION} already installed. Skipping."
            return 0
        else
            log "Go ${current_version} found, but ${GO_VERSION} requested. Upgrading..."
        fi
    fi

    local go_tarball="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    local go_url="https://go.dev/dl/${go_tarball}"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    log "Downloading Go ${GO_VERSION} for linux/${ARCH}..."
    curl -fsSL -o "${tmp_dir}/${go_tarball}" "${go_url}" \
        || die "Failed to download Go from ${go_url}"

    # Remove any previous installation
    rm -rf /usr/local/go

    log "Extracting Go to /usr/local/go..."
    tar -C /usr/local -xzf "${tmp_dir}/${go_tarball}"
    rm -rf "${tmp_dir}"

    # Ensure Go is on PATH for all users
    if [[ ! -f /etc/profile.d/go.sh ]]; then
        cat > /etc/profile.d/go.sh <<'GOEOF'
export PATH="/usr/local/go/bin:${PATH}"
GOEOF
        chmod 644 /etc/profile.d/go.sh
    fi

    # Make it available in this session
    export PATH="/usr/local/go/bin:${PATH}"

    log "Go $(go version) installed."
}

# ---------------------------------------------------------------------------
# Install Python dependencies inside a virtual environment
# ---------------------------------------------------------------------------
install_python_deps() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local req_file="${script_dir}/requirements.txt"

    if [[ ! -f "${req_file}" ]]; then
        log "WARNING: requirements.txt not found at ${req_file}. Installing known packages..."
        req_file=""
    fi

    # Create the virtual environment (idempotent: skips if it already exists)
    if [[ ! -d "${VENV_DIR}" ]]; then
        log "Creating Python virtual environment at ${VENV_DIR}..."
        python3 -m venv "${VENV_DIR}"
    else
        log "Virtual environment already exists at ${VENV_DIR}."
    fi

    # Activate the venv for the remainder of this script
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    log "Installing Python dependencies inside venv..."
    pip install --upgrade pip 2>/dev/null || true
    if [[ -n "${req_file}" ]]; then
        pip install -r "${req_file}"
    else
        pip install psutil matplotlib seaborn pandas numpy
    fi

    log "Python dependencies installed inside ${VENV_DIR}."
}

# ---------------------------------------------------------------------------
# Pre-compile the Go benchmark tool (optional but saves time on first run)
# ---------------------------------------------------------------------------
precompile_go_tool() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local go_file="${script_dir}/utils/benchmark_tool.go"

    if [[ ! -f "${go_file}" ]]; then
        log "WARNING: benchmark_tool.go not found at ${go_file}. Skipping pre-compilation."
        return 0
    fi

    log "Pre-compiling benchmark_tool.go (downloading Go modules & caching build)..."
    # `go build` is used instead of `go run` to cache the compilation.
    # The acceptance_test.sh uses `go run` which benefits from the cached build.
    (cd "$(dirname "${go_file}")" && go build -o /dev/null benchmark_tool.go) \
        || log "WARNING: Pre-compilation failed. benchmark_tool.go will be compiled on first run."

    log "Pre-compilation done."
}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
verify() {
    local errors=0

    log "Verifying installation..."

    # Ensure the venv is active for verification
    if [[ -f "${VENV_DIR}/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "${VENV_DIR}/bin/activate"
        log "  [OK] venv active: ${VENV_DIR}"
    else
        log "  [FAIL] venv not found at ${VENV_DIR}"; errors=$((errors + 1))
    fi

    # Python 3
    if command -v python3 &>/dev/null; then
        log "  [OK] python3: $(python3 --version) ($(command -v python3))"
    else
        log "  [FAIL] python3 not found"; errors=$((errors + 1))
    fi

    # pip
    if python3 -m pip --version &>/dev/null; then
        log "  [OK] pip: $(python3 -m pip --version 2>&1 | head -1)"
    else
        log "  [FAIL] pip not found"; errors=$((errors + 1))
    fi

    # Go
    if command -v go &>/dev/null; then
        log "  [OK] go: $(go version)"
    else
        log "  [FAIL] go not found"; errors=$((errors + 1))
    fi

    # curl
    if command -v curl &>/dev/null; then
        log "  [OK] curl: $(curl --version | head -1)"
    else
        log "  [FAIL] curl not found"; errors=$((errors + 1))
    fi

    # pgrep
    if command -v pgrep &>/dev/null; then
        log "  [OK] pgrep available"
    else
        log "  [FAIL] pgrep not found"; errors=$((errors + 1))
    fi

    # dmidecode
    if command -v dmidecode &>/dev/null; then
        log "  [OK] dmidecode available"
    else
        log "  [WARN] dmidecode not found (system_report RAM info will be N/A)"
    fi

    # Python packages
    local py_pkgs=(psutil matplotlib seaborn pandas numpy)
    for pkg in "${py_pkgs[@]}"; do
        if python3 -c "import ${pkg}" 2>/dev/null; then
            log "  [OK] python3 -c 'import ${pkg}'"
        else
            log "  [FAIL] Python package '${pkg}' not importable"; errors=$((errors + 1))
        fi
    done

    if [[ $errors -gt 0 ]]; then
        die "${errors} verification check(s) failed."
    fi

    log "All checks passed. Ready to run acceptance_test.sh."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "============================================================"
    log "  Benchmark Dependencies Installer"
    log "  OS:   ${OS_NAME}"
    log "  Arch: ${ARCH}"
    log "  Go:   ${GO_VERSION}"
    log "============================================================"

    install_system_packages
    install_go
    install_python_deps
    precompile_go_tool
    verify

    log ""
    log "============================================================"
    log "  Setup complete!"
    log "  Virtual environment: ${VENV_DIR}"
    log "  You can now run: ./acceptance_test.sh"
    log "  (the venv is activated automatically by the scripts)"
    log "============================================================"
}

main "$@"
