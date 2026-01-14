#!/bin/bash
log_error() {
   echo "Error: $1"
   exit 1
 }

set_utils(){
    if [ -n "$(command -v rpm)" ]; then
        install="rpm -ivh --ignorearch"
        uninstall="rpm -ev"
        check_package_status='rpm -q'
        package_extension="rpm"
    elif [ -n "$(command -v dpkg)" ]; then
        install="dpkg --install"
        uninstall="dpkg --purge"
        check_package_status='dpkg-query -W'
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

    if [ -z "$requested_package_operation" ] || { [ "$requested_package_operation" != "install" ] && [ "$requested_package_operation" != "uninstall" ]; }; then
        log_error "Missing package operation or not supported"
    fi

    if [ "$requested_package_operation" == "install" ]; then
        $install "$package_path"
    else
        $uninstall "$package_path"
    fi
}

set_dummy_manager_ip(){
    sed -i 's/MANAGER_IP/1.1.1.1/g' /var/ossec/etc/ossec.conf
}

save_package_manager_package_status(){
    output=$($check_package_status "wazuh-agent" 2>&1)
    echo "$output" | tee /packages/package_manager_package_status.log
}

start_agent(){
    /var/ossec/bin/wazuh-control start
}

check_test_results(){
    if [ "$package_extension" == "rpm" ]; then
        if grep -iq "not installed" /packages/package_manager_package_status.log ; then
            echo "Package correctly removed."
        else
            log_error "Package uninstallation failed."
        fi
    else
        if grep -iq "no packages found" /packages/package_manager_package_status.log ; then
            echo "Package correctly removed."
        else
            log_error "Package uninstallation failed."
        fi
    fi
}

main() {
    set_utils
    package_name="/packages/$(ls /packages | grep "wazuh.*$package_extension$" | grep -Ev "dbg|debug")"
    package_operation "$package_name" "install"
    set_dummy_manager_ip
    start_agent
    package_operation "wazuh-agent" "uninstall"
    save_package_manager_package_status
    check_test_results
}

main
