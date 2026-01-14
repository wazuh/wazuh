#!/bin/bash
log_error() {
   echo "Error: $1"
   exit 1
 }

set_utils(){
    if [ -n "$(command -v rpm)" ]; then
        install="rpm -ivh --ignorearch"
        upgrade="rpm -Uvh --ignorearch"
        get_package_version='rpm -q --qf %{VERSION}\n'
        package_extension="rpm"
    elif [ -n "$(command -v dpkg)" ]; then
        install="dpkg --install"
        upgrade="$install --force-confnew"
        get_package_version='dpkg-query -W -f=${version}\n'
        package_extension="deb"
    else
        log_error "Couldn't find type of system"
    fi
}

package_operation(){
    local package_path=$1
    local requested_package_operation=$2

    if [ -z "$package_path" ]; then
        log_error "No package found to install"
    fi

    if [ -z "$requested_package_operation" ] || { [ "$requested_package_operation" != "install" ] && [ "$requested_package_operation" != "upgrade" ]; }; then
        log_error "Missing package operation or not supported"
    fi

    if [ "$requested_package_operation" == "install" ]; then
        $install "$package_path"
    else
        $upgrade "$package_path"
    fi
}

set_dummy_manager_ip(){
    sed -i 's/MANAGER_IP/1.1.1.1/g' /var/ossec/etc/ossec.conf
}

download_package(){
    local package_url=$1
    mkdir -p /old_package
    if ! curl -o /old_package/$(basename "$package_url") $package_url; then
        log_error "Failed to download the package from $package_url"
    fi
}

save_package_manager_upgraded_version(){
    if ! output=$($get_package_version "wazuh-agent"); then
        log_error "Failed to get package version"
    fi
    output="${output%%-*}"
    echo "$output" | tee /packages/package_manager_upgraded_version.log
}

save_agent_reported_version(){
    if ! output=$(/var/ossec/bin/wazuh-control info); then
        log_error "Failed to get agent info"
    fi
    echo "$output" | tee /packages/agent_reported_version.log
}

save_agent_daemons_status(){
    if ! output=$(/var/ossec/bin/wazuh-control status); then
        log_error "Error: Failed to get agent status"
    fi
    echo "$output" | tee /packages/agent_daemon_status.log
}

start_agent(){
    /var/ossec/bin/wazuh-control start
}

check_test_results(){
    local expected_upgrade_version=$1
    if grep -iq $expected_upgrade_version /packages/package_manager_upgraded_version.log ; then
        echo "Updated package version succesfully reported by package manager."
    else
        log_error "Package manager does not report expected version."
    fi

    if grep -iq $expected_upgrade_version /packages/agent_reported_version.log ; then
        echo "Updated package version succesfully reported by agent."
    else
        log_error "Agent does not report expected version."
    fi

    services=("wazuh-execd" "wazuh-agentd" "wazuh-syscheckd" "wazuh-logcollector" "wazuh-modulesd")
    all_started=true

    for service in "${services[@]}"; do
        if ! grep -iq "$service is running" /packages/agent_daemon_status.log; then
            all_started=false
            break
        fi
    done

    if $all_started ; then
        echo "All daemons are properly running after upgrade."
    else
        log_error "Some daemon failed to start after upgrade."
    fi
}

main() {
    OLD_PACKAGE_URL="$1"
    EXPECTED_UPGRADE_VERSION="$2"
    if [ -z "$OLD_PACKAGE_URL" ]; then
        log_error "Missing package URL. Usage: $0 <package_url> <expected_upgrade_version>"
    fi
    set_utils
    download_package "$OLD_PACKAGE_URL"
    package_operation "/old_package/$(basename "$OLD_PACKAGE_URL")" "install"
    set_dummy_manager_ip
    package_operation "/packages/$(ls /packages | grep "wazuh.*$package_extension$" | grep -Ev "dbg|debug")" "upgrade"
    start_agent
    save_package_manager_upgraded_version
    save_agent_reported_version
    save_agent_daemons_status
    check_test_results "$EXPECTED_UPGRADE_VERSION"
}

main "$@"
