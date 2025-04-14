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

save_upgraded_version(){
    if ! output=$($get_package_version "wazuh-agent"); then
        echo "Error: Failed to get package version"
        exit 1
    fi
    output="${output%%-*}"
    echo "$output" | tee /packages/upgraded_version.log
}

main() {
    if [ -z "$1" ]; then
        echo "Error: Missing package URL. Usage: $0 <package_url>"
        exit 1
    fi
    OLD_PACKAGE_URL="$1"
    set_utils
    download_package "$OLD_PACKAGE_URL"
    package_operation "/old_package/$(basename "$OLD_PACKAGE_URL")" "install"
    set_dummy_manager_ip
    package_operation "/packages/$(ls /packages | grep "wazuh.*$package_extension$" | grep -Ev "dbg|debug")" "upgrade"
    save_upgraded_version
}

main "$@"
