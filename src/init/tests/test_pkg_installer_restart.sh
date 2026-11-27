#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the RPM install and the restart decision of pkg_installer.sh against a throwaway install
# directory. rpm, curl and wazuh-control are stubs; wazuh-agentd is a sleeping process whose argv[0]
# is the tree's bin/wazuh-agentd, with its pid file in var/run, as the real daemon leaves them.
# What the stub rpm's install does to that process is what each case chooses:
#
#   noop      installs nothing and leaves the daemon running, as a freshen of the installed
#             version did
#   restart   stops the daemon and starts a new one, as the package's %pre/%posttrans do
#
#   ./test_pkg_installer_restart.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
trap 'for p in $(cat "${WORK}"/*/agentd.pids 2>/dev/null); do kill "${p}" 2>/dev/null; done; rm -rf "${WORK}"' EXIT

LEGACY_CONF='<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
    </server>
  </client>
</ossec_config>
'

# What wazuh-agentd writes (write_state(), src/client-agent/src/state.c).
CONNECTED_STATE="status='connected'
"

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

# Starts a fake wazuh-agentd in tree $1 and writes its pid file, as the daemon does.
start_agentd() {

    local dir="$1"

    bash -c 'exec -a "$0" sleep 300' "${dir}/bin/wazuh-agentd" > /dev/null 2>&1 &
    echo "$!" >> "${dir}/agentd.pids"
    : > "${dir}/var/run/wazuh-agentd-$!.pid"

}

# A PATH holding the system's tools, and stubs for:
#   rpm   -q --qf answers a 4.x agent version, so the TLS gate lets the upgrade through; -q
#         wazuh-agent answers whether the RPM is installed (the tree's rpm-installed file); an
#         install records its arguments in rpm.calls and runs the case's hook (rpm-hook)
#   curl  answers the connectivity check (-k) with 0 and the system-store check with 60
make_path() {

    local dir="$1" bin="$1/path"

    mkdir -p "${bin}"
    for tool in /usr/bin/* /bin/* /usr/sbin/* /sbin/*; do
        [ -x "${tool}" ] && [ ! -e "${bin}/$(basename "${tool}")" ] && ln -s "${tool}" "${bin}/" 2>/dev/null
    done
    rm -f "${bin}/curl" "${bin}/wget" "${bin}/rpm" "${bin}/dpkg-query" "${bin}/dpkg"

    cat > "${bin}/rpm" <<EOF
#!/bin/bash
case "\$1" in
    -q)
        if [ "\$2" = "--qf" ]; then echo 4.14.7; exit 0; fi
        [ -f "${dir}/rpm-installed" ]
        exit \$?
        ;;
    -U*|-F*|-i*)
        echo "\$*" >> "${dir}/rpm.calls"
        [ -x "${dir}/rpm-hook" ] && "${dir}/rpm-hook"
        exit 0
        ;;
esac
exit 0
EOF
    printf '#!/bin/sh\nfor arg in "$@"; do [ "${arg}" = "-k" ] && exit 0; done\nexit 60\n' > "${bin}/curl"
    chmod +x "${bin}/rpm" "${bin}/curl"

}

# Runs the target against a fresh tree with a running fake wazuh-agentd. $2 is the install's
# effect (noop or restart), $3 "installed" when the wazuh-agent RPM is installed.
run_case() {

    local name="$1" effect="$2" installed="$3"
    local dir="${WORK}/${name}"

    mkdir -p "${dir}/etc" "${dir}/logs" "${dir}/bin" "${dir}/var/upgrade" "${dir}/var/incoming" "${dir}/var/run"
    printf '%s' "${LEGACY_CONF}" > "${dir}/etc/ossec.conf"
    : > "${dir}/var/upgrade/wazuh-agent-5.0.0-1.x86_64.rpm"
    printf '%s' "${CONNECTED_STATE}" > "${dir}/var/run/wazuh-agentd.state"
    [ "${installed}" = "installed" ] && : > "${dir}/rpm-installed"

    # status reports what the real one does for a live wazuh-agentd; restart and reload are recorded.
    cat > "${dir}/bin/wazuh-control" <<EOF
#!/bin/bash
case "\$1" in
    status)
        for f in "${dir}"/var/run/wazuh-agentd-*.pid; do
            p="\${f##*/wazuh-agentd-}"; p="\${p%.pid}"
            kill -0 "\${p}" 2>/dev/null && { echo "wazuh-agentd is running..."; exit 0; }
        done
        echo "wazuh-agentd not running..."
        ;;
    *) echo "\$1" >> "${dir}/control.calls" ;;
esac
exit 0
EOF
    chmod +x "${dir}/bin/wazuh-control"

    if [ "${effect}" = "restart" ]; then
        cat > "${dir}/rpm-hook" <<EOF
#!/bin/bash
for f in "${dir}"/var/run/wazuh-agentd-*.pid; do
    p="\${f##*/wazuh-agentd-}"; p="\${p%.pid}"
    kill "\${p}" 2>/dev/null
    rm -f "\${f}"
done
bash -c 'exec -a "\$0" sleep 300' "${dir}/bin/wazuh-agentd" > /dev/null 2>&1 &
echo "\$!" >> "${dir}/agentd.pids"
: > "${dir}/var/run/wazuh-agentd-\$!.pid"
EOF
        chmod +x "${dir}/rpm-hook"
    fi

    start_agentd "${dir}"
    make_path "${dir}"

    (cd "${dir}" && env -i PATH="${dir}/path" HOME="${dir}" INSTALLDIR="${dir}" bash "${TARGET}" > /dev/null 2>&1)

}

log_count() {

    grep -c -E -- "$2" "${WORK}/$1/logs/upgrade.log"

}

calls() {

    cat "${WORK}/$1/$2" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'

}

# A forced upgrade to the installed version: the package must really be reinstalled, so neither a
# freshen (-F) nor a plain -U, which install nothing at the same version.
run_case same_version noop installed
check "the RPM is installed with --replacepkgs --oldpackage" \
    "-Uvh --replacepkgs --oldpackage ./var/upgrade/wazuh-agent-5.0.0-1.x86_64.rpm" "$(calls same_version rpm.calls)"
check "a daemon the install left running is restarted" "restart" "$(calls same_version control.calls)"
check "the old daemon still running is logged" "1" "$(log_count same_version "pre-upgrade wazuh-agentd \(pid [0-9]+\) is still running after the install")"
check "the old daemon is not taken for a package restart" "0" "$(log_count same_version "restarted by the package installer")"

# The package's hooks restarted the daemon: no second restart.
run_case hooks_restarted restart installed
check "a daemon the package restarted is not restarted again" "" "$(calls hooks_restarted control.calls)"
check "the package restart is logged" "1" "$(log_count hooks_restarted "restarted by the package installer")"
check "the upgrade finishes" "1" "$(log_count hooks_restarted "Upgrade finished successfully")"

# An agent not installed from the RPM: nothing is installed, and the upgrade fails instead of
# reporting a success.
run_case not_rpm noop missing
check "nothing is installed over an agent not installed from the RPM" "" "$(calls not_rpm rpm.calls)"
check "the missing RPM is logged" "1" "$(log_count not_rpm "the wazuh-agent RPM is not installed")"
check "the upgrade result is 2" "2" "$(cat "${WORK}/not_rpm/var/upgrade/upgrade_result" 2>/dev/null)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
