#!/usr/bin/env bash
# Copyright (C) 2015, Wazuh Inc.
# Purge script for Wazuh
#
# Usage:
#   sudo ./purge_wazuh.sh
#
# Behavior:
#   1. If wazuh-agent or wazuh-manager packages are installed, purge them.
#   2. Always perform a final cleanup of service units, users/groups and
#      installation directories.
#   3. If no packages are installed, treat the system as a source/manual
#      installation and perform the same full cleanup directly.

readonly DEFAULT_WAZUH_AGENT_DIR="/var/ossec"
readonly DEFAULT_WAZUH_MANAGER_DIR="/var/wazuh-manager"

PKG_MANAGER=""
INSTALL_DIRS=()
PACKAGE_NAMES=()

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: This script must be run as root."
        echo "       Try: sudo $0"
        exit 1
    fi
}

append_install_dir() {
    local candidate="$1"
    local existing=""

    [ -n "$candidate" ] || return 0

    for existing in "${INSTALL_DIRS[@]}"; do
        [ "$existing" = "$candidate" ] && return 0
    done

    INSTALL_DIRS+=("$candidate")
}

init_install_dirs() {
    INSTALL_DIRS=()

    append_install_dir "${DEFAULT_WAZUH_MANAGER_DIR}"
    append_install_dir "${DEFAULT_WAZUH_AGENT_DIR}"
    append_install_dir "${WAZUH_HOME:-}"
    detect_install_dirs_from_services
}

detect_install_dirs_from_services() {
    local service_file=""
    local detected_dir=""

    for service_file in \
        /etc/systemd/system/wazuh-manager.service \
        /etc/systemd/system/wazuh-agent.service \
        /usr/lib/systemd/system/wazuh-manager.service \
        /usr/lib/systemd/system/wazuh-agent.service \
        /lib/systemd/system/wazuh-manager.service \
        /lib/systemd/system/wazuh-agent.service \
        /etc/init.d/wazuh-manager \
        /etc/init.d/wazuh-agent \
        /etc/rc.d/init.d/wazuh-manager \
        /etc/rc.d/init.d/wazuh-agent; do
        [ -f "${service_file}" ] || continue

        case "${service_file}" in
            *.service)
                detected_dir=$(
                    sed -n 's|^ExecStart=/usr/bin/env \(.*\)/bin/[^[:space:]]*control start$|\1|p' "${service_file}" |
                        head -n 1
                )
                ;;
            *)
                detected_dir=$(sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' "${service_file}" | head -n 1)
                ;;
        esac

        append_install_dir "${detected_dir}"
    done
}

stop_services() {
    local service_name=""
    local install_dir=""

    if command -v systemctl >/dev/null 2>&1; then
        for service_name in wazuh-manager wazuh-agent wazuh-local; do
            systemctl stop "${service_name}" 2>/dev/null || true
            systemctl disable "${service_name}" 2>/dev/null || true
        done
    fi

    if command -v service >/dev/null 2>&1; then
        service wazuh-manager stop 2>/dev/null || true
        service wazuh-agent stop 2>/dev/null || true
        service wazuh-local stop 2>/dev/null || true
    fi

    for install_dir in "${INSTALL_DIRS[@]}"; do
        [ -x "${install_dir}/bin/wazuh-manager-control" ] && \
            "${install_dir}/bin/wazuh-manager-control" stop 2>/dev/null || true
        [ -x "${install_dir}/bin/wazuh-control" ] && \
            "${install_dir}/bin/wazuh-control" stop 2>/dev/null || true
    done

    if command -v pkill >/dev/null 2>&1; then
        pkill -9 -f 'wazuh-manager-authd|wazuh-manager-remoted|wazuh-manager-monitord|wazuh-manager-modulesd|wazuh-manager-analysisd|wazuh-manager-db|wazuh_manager_apid|wazuh_manager_clusterd' 2>/dev/null || true
        pkill -9 -f 'wazuh-agentd|wazuh-syscheckd|wazuh-logcollector|wazuh-execd|wazuh-modulesd' 2>/dev/null || true
    fi
}

unmount_dev_proc() {
    local install_dir=""
    local proc_dir=""

    command -v mountpoint >/dev/null 2>&1 || return 0

    for install_dir in "${INSTALL_DIRS[@]}"; do
        proc_dir="${install_dir}/proc"

        if [ -d "${proc_dir}" ] && mountpoint -q "${proc_dir}"; then
            echo " - Unmounting ${proc_dir}"
            umount "${proc_dir}" 2>/dev/null || true
        fi
    done
}

detect_packages() {
    local packages=""

    PKG_MANAGER=""
    PACKAGE_NAMES=()

    if command -v dpkg-query >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        packages=$(
            dpkg-query -W -f='${Package}\t${Status}\n' 2>/dev/null |
                awk '$4=="installed" && ($1=="wazuh-manager" || $1=="wazuh-agent") {print $1}' |
                tr '\n' ' '
        )
    elif command -v rpm >/dev/null 2>&1; then
        if command -v dnf >/dev/null 2>&1; then
            PKG_MANAGER="dnf"
        elif command -v yum >/dev/null 2>&1; then
            PKG_MANAGER="yum"
        elif command -v zypper >/dev/null 2>&1; then
            PKG_MANAGER="zypper"
        else
            PKG_MANAGER="rpm"
        fi

        packages=$(
            rpm -qa 2>/dev/null |
                grep -E '^wazuh-(manager|agent)(-|$)' |
                tr '\n' ' ' || true
        )
    fi

    [ -n "${packages}" ] && read -r -a PACKAGE_NAMES <<<"${packages}"
}

purge_packages() {
    [ "${#PACKAGE_NAMES[@]}" -gt 0 ] || return 0

    echo " - Removing packages: ${PACKAGE_NAMES[*]}"

    case "${PKG_MANAGER}" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get purge --no-auto-remove -y "${PACKAGE_NAMES[@]}" 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null || true
            apt-get autoclean -y 2>/dev/null || true
            ;;
        dnf)
            dnf remove -y "${PACKAGE_NAMES[@]}" 2>/dev/null || true
            ;;
        yum)
            yum remove -y "${PACKAGE_NAMES[@]}" 2>/dev/null || true
            ;;
        zypper)
            zypper --non-interactive remove -u "${PACKAGE_NAMES[@]}" 2>/dev/null || true
            ;;
        rpm)
            rpm -e --nodeps "${PACKAGE_NAMES[@]}" 2>/dev/null || true
            ;;
    esac
}

remove_install_dirs() {
    local install_dir=""

    for install_dir in "${INSTALL_DIRS[@]}"; do
        if [ -d "${install_dir}" ]; then
            echo " - Removing ${install_dir}"
            rm -rf -- "${install_dir}"
        fi
    done
}

remove_service_units() {
    local service_dir=""
    local init_dir=""
    local init_name=""

    if [ -f /etc/rc.local ]; then
        sed -i '/wazuh-control start/d;/wazuh-manager-control start/d;/wazuh-local-control start/d' /etc/rc.local 2>/dev/null || true
    fi

    for init_dir in /etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d; do
        [ -d "${init_dir}" ] || continue
        for init_name in wazuh-manager wazuh-agent wazuh-local; do
            rm -f \
                "${init_dir}/${init_name}" \
                "${init_dir}"/S??"${init_name}" \
                "${init_dir}"/K??"${init_name}" 2>/dev/null || true
        done
    done

    if command -v systemctl >/dev/null 2>&1; then
        for service_dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
            [ -d "${service_dir}" ] || continue
            find "${service_dir}" -maxdepth 2 \( \
                -name 'wazuh-manager.service' -o \
                -name 'wazuh-agent.service' -o \
                -name 'wazuh-local.service' \
            \) -exec rm -f {} + 2>/dev/null || true
        done

        systemctl daemon-reload 2>/dev/null || true
        systemctl reset-failed 2>/dev/null || true
    fi
}

remove_misc_files() {
    [ -e /etc/ossec-init.conf ] && rm -f /etc/ossec-init.conf
}

remove_users_groups() {
    local user_name=""
    local group_name=""

    for user_name in wazuh wazuh-manager; do
        if id "${user_name}" >/dev/null 2>&1; then
            echo " - Removing user: ${user_name}"
            userdel "${user_name}" 2>/dev/null || userdel -r "${user_name}" 2>/dev/null || true
        fi
    done

    for group_name in wazuh wazuh-manager; do
        if getent group "${group_name}" >/dev/null 2>&1; then
            echo " - Removing group: ${group_name}"
            groupdel "${group_name}" 2>/dev/null || true
        fi
    done
}

cleanup_system() {
    unmount_dev_proc
    remove_install_dirs
    remove_service_units
    remove_misc_files
    remove_users_groups
}

main() {
    echo ""
    echo " Wazuh purge script"
    echo " =================="
    echo ""

    require_root
    init_install_dirs

    echo " - Stopping Wazuh services..."
    stop_services

    echo " - Checking for installed packages..."
    detect_packages

    if [ "${#PACKAGE_NAMES[@]}" -gt 0 ]; then
        echo " - Package-managed installation detected."
        purge_packages

        echo " - Removing remaining Wazuh files..."
        cleanup_system
        echo ""
        echo " - Wazuh packages purged successfully."
    else
        echo " - No installed wazuh-manager/wazuh-agent packages detected."
        echo " - Performing source/manual cleanup."
        cleanup_system
        echo ""
        echo " - Source/manual installation removed successfully."
    fi

    echo ""
    echo " Wazuh purge completed."
    echo ""
}

main "$@"
