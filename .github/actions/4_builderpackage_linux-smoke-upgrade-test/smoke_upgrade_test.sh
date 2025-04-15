#!/bin/bash
set_utils(){
    if [ -n "$(command -v rpm)" ]; then
        install="rpm -ivh --ignorearch"
        upgrade="rpm -Uvh --ignorearch"
        get_package_version='rpm -q --qf %{VERSION}\n'
        package_extension="rpm"
    elif [ -n "$(command -v dpkg)" ]; then
        install="dpkg --install"
        upgrade=$install
        get_package_version='dpkg-query -W -f=${version}\n'
        package_extension="deb"
    else
        echo "Error: couldn't find type of system"
        exit 1
    fi
}

package_operation(){
    local package_path=$1
    local package_operation=$2

    if [ -z "$package_path" ]; then
        echo "Error: No package found to install"
        exit 1
    fi

    if [ -z "$package_operation" ] || { [ "$package_operation" != "install" ] && [ "$package_operation" != "upgrade" ]; }; then
        echo "Error: Missing package operation or not supported"
        exit 1
    fi

    if [ "$package_operation" == "install" ]; then
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
        echo "Error: Failed to download the package from $package_url"
        exit 1
    fi
}

save_package_manager_upgraded_version(){
    if ! output=$($get_package_version "wazuh-agent"); then
        echo "Error: Failed to get package version"
        exit 1
    fi
    output="${output%%-*}"
    echo "$output" | tee /packages/package_manager_upgraded_version.log
}

save_agent_reported_version(){
    if ! output=$(/var/ossec/bin/wazuh-control info); then
        echo "Error: Failed to get agent info"
        exit 1
    fi
    echo "$output" | tee /packages/agent_reported_version.log
}

save_agent_daemons_status(){
    if ! output=$(/var/ossec/bin/wazuh-control status); then
        echo "Error: Failed to get agent status"
        exit 1
    fi
    echo "$output" | tee /packages/agent_daemon_status.log
}

start_agent(){
    /var/ossec/bin/wazuh-control start
    sleep 10
}

check_test_results(){
    local expected_upgrade_version=$1
    if grep -iq $expected_upgrade_version /packages/package_manager_upgraded_version.log ; then
        echo "Updated package version succesfully reported by package manager."
    else
        echo "Error: Package manager does not report expected version."
        exit 1;
    fi

    if grep -iq $expected_upgrade_version /packages/agent_reported_version.log ; then
        echo "Updated package version succesfully reported by agent."
    else
        echo "Error: Agent does not report expected version."
        exit 1;
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
        echo "Error: Some daemon failed to start after upgrade."
        exit 1
    fi
}

main() {
    if [ -z "$1" ]; then
        echo "Error: Missing package URL. Usage: $0 <package_url> <expected_upgrade_version>"
        exit 1
    fi
    OLD_PACKAGE_URL="$1"
    EXPECTED_UPGRADE_VERSION="$2"
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
