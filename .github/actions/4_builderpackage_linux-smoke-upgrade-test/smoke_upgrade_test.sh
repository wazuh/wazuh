#!/bin/bash
set_utils(){
    if [ -n "$(command -v rpm)" ]; then
        install="rpm -ivh --force --ignorearch"
        get_package_version='rpm -q --qf %{VERSION}\n'
        package_extension="rpm"
    elif [ -n "$(command -v dpkg)" ]; then
        install="dpkg --install"
        get_package_version='dpkg-query -W -f=${version}\n'
        package_extension="deb"
    else
        echo "Error: couldn't find type of system"
        exit 1
    fi
}

install_package(){
    local installing_package_path=$1
    if [ -z "$installing_package_path" ]; then
        echo "Error: No package found to install"
        exit 1
    fi
    $install "$installing_package_path"
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
    install_package "/old_package/$(basename "$OLD_PACKAGE_URL")"
    set_dummy_manager_ip
    install_package "/packages/$(ls /packages | grep "wazuh.*$package_extension$" | grep -Ev "dbg|debug")"
    save_upgraded_version
}

main "$@"
