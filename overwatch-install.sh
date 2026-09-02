#!/bin/bash
# overwatch-install.sh
# One-command installer for Overwatch SIEM (manager + indexer + dashboard)
# Usage: curl -sO https://raw.githubusercontent.com/visot-io/overwatch-siem/main/overwatch-install.sh && sudo bash overwatch-install.sh

set -euo pipefail

REPO_URL="https://github.com/visot-io/overwatch-siem.git"
REPO_BRANCH="main"
INSTALL_DIR="/opt/overwatch-siem"
LOG_FILE="/var/log/overwatch-install.log"
WAZUH_VERSION="5.0.0"
WAZUH_PYTHON_VERSION="3.12"
MIN_RAM_GB=8
MIN_DISK_GB=50

# ── colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()   { echo -e "${CYAN}[overwatch]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()    { echo -e "${GREEN}[  OK  ]${RESET} $*"   | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[ WARN ]${RESET} $*"  | tee -a "$LOG_FILE"; }
die()   { echo -e "${RED}[ FAIL ]${RESET} $*"     | tee -a "$LOG_FILE"; exit 1; }

# ── banner ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Overwatch SIEM — Full Stack Installer            ║"
echo "║     Manager · Indexer · Dashboard                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── root check ─────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "This script must be run as root (use sudo)."

# ── log setup ──────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
log "Full build log → $LOG_FILE"

# ── OS detection ───────────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-linux}"
        OS_VER="${VERSION_ID:-0}"
    else
        OS_ID="linux"
        OS_VER="0"
    fi
}

# ── OS version validation ──────────────────────────────────────────────────────
validate_os() {
    case "$OS_ID" in
        ubuntu)
            [[ "$OS_VER" =~ ^(18|20|22|24) ]] \
                || warn "Ubuntu $OS_VER is not in the official support matrix (18/20/22/24.04)." ;;
        debian)
            [[ "$OS_VER" =~ ^(10|11|12) ]] \
                || warn "Debian $OS_VER is not in the official support matrix (10/11/12)." ;;
        rhel|centos|almalinux|rocky|ol)
            [[ "$OS_VER" =~ ^(7|8|9|10) ]] \
                || warn "RHEL/CentOS $OS_VER is not in the official support matrix (7/8/9/10)." ;;
        amzn)
            [[ "$OS_VER" =~ ^(2|2023) ]] \
                || warn "Amazon Linux $OS_VER is not in the official support matrix (2/2023)." ;;
        fedora) ;;
        *)
            warn "OS '$OS_ID' is not in the official Wazuh support matrix." ;;
    esac
}

# ── system requirements pre-flight ────────────────────────────────────────────
check_requirements() {
    log "Checking system requirements..."

    local ram_gb
    ram_gb=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
    [ "$ram_gb" -ge "$MIN_RAM_GB" ] \
        || die "Minimum ${MIN_RAM_GB} GB RAM required. Found ${ram_gb} GB."

    local disk_gb
    disk_gb=$(df -BG / | awk 'NR==2{gsub("G",""); print $4}')
    [ "$disk_gb" -ge "$MIN_DISK_GB" ] \
        || die "Minimum ${MIN_DISK_GB} GB free disk required. Found ${disk_gb} GB."

    # 64-bit arch required
    [ "$(uname -m)" = "x86_64" ] || die "Only x86_64 (64-bit) architecture is supported."

    ok "System OK — ${ram_gb} GB RAM, ${disk_gb} GB free disk, $(uname -m)."
}

# ── kernel tuning for OpenSearch ──────────────────────────────────────────────
tune_kernel() {
    log "Setting vm.max_map_count=262144 (required by OpenSearch/indexer)..."
    sysctl -w vm.max_map_count=262144 >> "$LOG_FILE" 2>&1
    grep -q "vm.max_map_count" /etc/sysctl.conf \
        && sed -i 's/^vm.max_map_count.*/vm.max_map_count=262144/' /etc/sysctl.conf \
        || echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    ok "vm.max_map_count set to 262144 (persisted in /etc/sysctl.conf)."
}

# ── build dependency installation ──────────────────────────────────────────────
install_build_deps() {
    log "Installing build dependencies..."
    case "$OS_ID" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >> "$LOG_FILE" 2>&1
            apt-get install -y -qq \
                git curl wget \
                gcc g++ make cmake ninja-build pkg-config \
                automake autoconf libtool \
                python3 python3-pip python3-dev python3-venv \
                libssl-dev libaudit-dev libffi-dev \
                zlib1g-dev libbz2-dev libsqlite3-dev \
                libncurses5-dev libreadline-dev liblzma-dev \
                libpcre2-dev libxml2-dev libdbus-1-dev \
                clang llvm \
                policycoreutils sqlite3 \
                gnupg lsb-release >> "$LOG_FILE" 2>&1
            apt-get install -y -qq "linux-headers-$(uname -r)" >> "$LOG_FILE" 2>&1 \
                || apt-get install -y -qq linux-headers-generic >> "$LOG_FILE" 2>&1 \
                || warn "linux-headers not installed — eBPF features may be limited."
            ;;
        rhel|centos|almalinux|rocky|ol)
            yum install -y \
                git curl wget gcc gcc-c++ make cmake \
                automake autoconf libtool \
                python3 python3-pip \
                openssl-devel audit-libs-devel \
                policycoreutils sqlite \
                gnupg2 >> "$LOG_FILE" 2>&1
            ;;
        amzn)
            yum install -y \
                git curl wget gcc gcc-c++ make cmake3 \
                automake autoconf libtool \
                python3 python3-pip \
                openssl-devel audit-libs-devel \
                policycoreutils sqlite >> "$LOG_FILE" 2>&1
            command -v cmake > /dev/null 2>&1 \
                || ln -sf "$(command -v cmake3)" /usr/local/bin/cmake
            ;;
        fedora)
            dnf install -y \
                git curl wget gcc gcc-c++ make cmake \
                automake autoconf libtool \
                python3 python3-pip \
                openssl-devel audit-libs-devel \
                policycoreutils sqlite >> "$LOG_FILE" 2>&1
            ;;
        *)
            warn "Unrecognised OS '$OS_ID'. Assuming build tools are present."
            ;;
    esac
    ok "Build dependencies installed."
}

# ── Docker + Compose installation ─────────────────────────────────────────────
install_docker() {
    if command -v docker > /dev/null 2>&1; then
        ok "Docker already installed ($(docker --version | awk '{print $3}' | tr -d ','))."
    else
        log "Installing Docker..."
        case "$OS_ID" in
            ubuntu|debian)
                apt-get install -y -qq ca-certificates >> "$LOG_FILE" 2>&1
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
                    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg >> "$LOG_FILE" 2>&1
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
                    > /etc/apt/sources.list.d/docker.list
                apt-get update -qq >> "$LOG_FILE" 2>&1
                apt-get install -y -qq \
                    docker-ce docker-ce-cli containerd.io docker-compose-plugin >> "$LOG_FILE" 2>&1
                ;;
            rhel|centos|almalinux|rocky|ol)
                yum install -y yum-utils >> "$LOG_FILE" 2>&1
                yum-config-manager --add-repo \
                    https://download.docker.com/linux/centos/docker-ce.repo >> "$LOG_FILE" 2>&1
                yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >> "$LOG_FILE" 2>&1
                ;;
            amzn)
                amazon-linux-extras install docker -y >> "$LOG_FILE" 2>&1 || \
                    dnf install -y docker >> "$LOG_FILE" 2>&1
                ;;
            *)
                curl -fsSL https://get.docker.com | sh >> "$LOG_FILE" 2>&1
                ;;
        esac
        systemctl enable --now docker >> "$LOG_FILE" 2>&1
        ok "Docker installed."
    fi

    if ! docker compose version > /dev/null 2>&1; then
        log "Installing Docker Compose plugin..."
        mkdir -p /usr/local/lib/docker/cli-plugins
        COMPOSE_VER=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest \
            | grep '"tag_name"' | cut -d'"' -f4)
        curl -fsSL \
            "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-linux-x86_64" \
            -o /usr/local/lib/docker/cli-plugins/docker-compose >> "$LOG_FILE" 2>&1
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
        ok "Docker Compose plugin installed."
    else
        ok "Docker Compose already available."
    fi
}

# ── clone or locate the repo ───────────────────────────────────────────────────
prepare_source() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/install.sh" ] && [ -d "$SCRIPT_DIR/src" ]; then
        SOURCE_DIR="$SCRIPT_DIR"
        log "Using existing source tree at $SOURCE_DIR"
        return
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating existing clone at $INSTALL_DIR..."
        git -C "$INSTALL_DIR" fetch origin "$REPO_BRANCH" >> "$LOG_FILE" 2>&1
        git -C "$INSTALL_DIR" checkout "$REPO_BRANCH"    >> "$LOG_FILE" 2>&1
        git -C "$INSTALL_DIR" pull origin "$REPO_BRANCH" >> "$LOG_FILE" 2>&1
    else
        log "Cloning repository (branch: $REPO_BRANCH)..."
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" >> "$LOG_FILE" 2>&1
    fi
    SOURCE_DIR="$INSTALL_DIR"
    ok "Source ready at $SOURCE_DIR"
}

# ── download external C/C++ dependencies ──────────────────────────────────────
fetch_external_deps() {
    local src_dir="$SOURCE_DIR/src"
    local already_fetched
    already_fetched=$(find "$src_dir/external" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)

    if [ "$already_fetched" -gt 0 ]; then
        ok "External dependencies already present ($already_fetched dirs). Skipping download."
        return
    fi

    log "Downloading external C/C++ dependencies from Wazuh CDN..."
    log "This is a one-time step and may take several minutes."
    (
        cd "$src_dir"
        make deps TARGET=manager >> "$LOG_FILE" 2>&1 \
            || { warn "First attempt failed — retrying..."; make deps TARGET=manager >> "$LOG_FILE" 2>&1; }
    )
    ok "External dependencies downloaded."
}

# ── run the upstream installer (unattended) ────────────────────────────────────
run_installer() {
    log "Building and installing Overwatch SIEM manager (this will take a while)..."
    (
        cd "$SOURCE_DIR"
        THREADS=$(nproc 2>/dev/null || echo 2)
        THREADS=$THREADS bash install.sh >> "$LOG_FILE" 2>&1
    )
    ok "Manager installation complete."
}

# ── generate indexer TLS certificates ─────────────────────────────────────────
generate_indexer_certs() {
    local cert_dir="/var/wazuh-manager/etc/certs"

    # Names must match what master_wazuh-manager_conf.xml references
    if [ -f "$cert_dir/root-ca.pem" ] && \
       [ -f "$cert_dir/wazuh.manager.pem" ] && \
       [ -f "$cert_dir/wazuh.manager-key.pem" ]; then
        ok "Indexer certs already present. Skipping generation."
        return
    fi

    log "Generating self-signed TLS certificates for indexer module..."
    mkdir -p "$cert_dir"

    # Root CA
    openssl genrsa -out "$cert_dir/root-ca-key.pem" 2048 >> "$LOG_FILE" 2>&1
    openssl req -new -x509 -days 3650 \
        -key  "$cert_dir/root-ca-key.pem" \
        -out  "$cert_dir/root-ca.pem" \
        -subj "/CN=Overwatch-CA/O=Overwatch SIEM/C=US" >> "$LOG_FILE" 2>&1

    # Manager cert — filenames match manager XML config
    openssl genrsa -out "$cert_dir/wazuh.manager-key.pem" 2048 >> "$LOG_FILE" 2>&1
    openssl req -new \
        -key  "$cert_dir/wazuh.manager-key.pem" \
        -out  "$cert_dir/wazuh.manager.csr" \
        -subj "/CN=wazuh-manager/O=Overwatch SIEM/C=US" >> "$LOG_FILE" 2>&1
    openssl x509 -req -days 3650 \
        -in   "$cert_dir/wazuh.manager.csr" \
        -CA   "$cert_dir/root-ca.pem" \
        -CAkey "$cert_dir/root-ca-key.pem" \
        -CAcreateserial \
        -out  "$cert_dir/wazuh.manager.pem" >> "$LOG_FILE" 2>&1
    rm -f "$cert_dir/wazuh.manager.csr" "$cert_dir/root-ca.srl"

    chmod 640 "$cert_dir"/*.pem
    chown -R root:wazuh-manager "$cert_dir" 2>/dev/null || \
        chown -R root:wazuh      "$cert_dir" 2>/dev/null || true

    ok "Indexer TLS certs written to $cert_dir"
}

# ── write .env for docker compose ─────────────────────────────────────────────
write_env() {
    local env_file="$SOURCE_DIR/api/tools/env/.env"

    # Calculate JVM heap = half of system RAM, capped at 32 GB
    local ram_gb heap_gb
    ram_gb=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
    heap_gb=$(( ram_gb / 2 ))
    [ "$heap_gb" -lt 1 ] && heap_gb=1
    [ "$heap_gb" -gt 32 ] && heap_gb=32

    # Generate a unique cluster key for this deployment
    local cluster_key
    cluster_key=$(openssl rand -hex 16)

    log "Writing docker compose .env (JVM heap: ${heap_gb}g, cluster key: generated)..."
    cat > "$env_file" <<EOF
WAZUH_BRANCH=${REPO_BRANCH}
WAZUH_VERSION=${WAZUH_VERSION}
WAZUH_PYTHON_VERSION=${WAZUH_PYTHON_VERSION}
WAZUH_LOCAL_PATH=${SOURCE_DIR}
OPENSEARCH_JAVA_OPTS=-Xms${heap_gb}g -Xmx${heap_gb}g
CLUSTER_KEY=${cluster_key}
EOF
    ok ".env written (heap=${heap_gb}g)."
}

# ── start indexer and dashboard ───────────────────────────────────────────────
start_stack() {
    local compose_dir="$SOURCE_DIR/api/tools/env"
    log "Building Overwatch dashboard image..."
    docker compose -f "$compose_dir/docker-compose.yml" \
        build --no-cache wazuh.dashboard >> "$LOG_FILE" 2>&1
    ok "Dashboard image built."

    log "Starting Wazuh Indexer..."
    docker compose -f "$compose_dir/docker-compose.yml" \
        up -d --no-deps wazuh.indexer >> "$LOG_FILE" 2>&1

    log "Waiting for Indexer to become healthy (up to 3 min)..."
    local tries=0
    until docker compose -f "$compose_dir/docker-compose.yml" \
            ps wazuh.indexer 2>/dev/null | grep -q "healthy" || [ $tries -ge 36 ]; do
        sleep 5; tries=$((tries+1))
    done
    [ $tries -ge 36 ] \
        && warn "Indexer health check timed out — starting dashboard anyway." \
        || ok "Indexer is healthy."

    log "Starting Overwatch Dashboard..."
    docker compose -f "$compose_dir/docker-compose.yml" \
        up -d --no-deps wazuh.dashboard >> "$LOG_FILE" 2>&1
    ok "Dashboard started."
}

# ── post-install summary ───────────────────────────────────────────────────────
print_summary() {
    local manager_dir="/var/wazuh-manager"
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Overwatch SIEM installed successfully!${RESET}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Dashboard UI:${RESET}  https://${server_ip}"
    echo -e "  ${BOLD}Credentials:${RESET}   admin / admin"
    echo -e "  ${YELLOW}  ⚠  Change default credentials after first login!${RESET}"
    echo ""
    echo -e "  ${BOLD}Manager control:${RESET}"
    echo "    Start  → $manager_dir/bin/wazuh-manager-control start"
    echo "    Stop   → $manager_dir/bin/wazuh-manager-control stop"
    echo "    Status → $manager_dir/bin/wazuh-manager-control status"
    echo ""
    echo -e "  ${BOLD}Ports:${RESET}"
    echo "    443   — Dashboard (HTTPS)"
    echo "    1514  — Agent data (TCP)"
    echo "    1515  — Agent enrollment (TCP)"
    echo "    55000 — Manager API (HTTPS)"
    echo "    9200  — Indexer / OpenSearch (HTTPS)"
    echo ""
    echo -e "  ${BOLD}Config:${RESET}   $manager_dir/etc/ossec.conf"
    echo -e "  ${BOLD}Logs:${RESET}     $manager_dir/logs/ossec.log"
    echo ""
    echo -e "  Build log → $LOG_FILE"
    echo ""
}

# ── main ───────────────────────────────────────────────────────────────────────
main() {
    detect_os
    log "Detected OS: $OS_ID $OS_VER"
    validate_os
    check_requirements
    tune_kernel

    install_build_deps
    install_docker
    prepare_source
    fetch_external_deps
    run_installer
    generate_indexer_certs
    write_env
    start_stack
    print_summary
}

main "$@"
