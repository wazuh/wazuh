#!/bin/bash

# 1. Check if the Wazuh agent is installed; if so, remove it.
# 2. Retrieve the latest version of the Wazuh agent package.
# 3. Install the latest version of the Wazuh agent.
# 4. Verify successful installation and start the agent.
# 5. Upgrade: Upgrade to the latest version using the builder package.
# 6. Verify successful upgrade and start the agent.
# 7. Verify the updated version.
# 8. Check if the wazuh-agent service is running.


# Input:
old_package_url=$1
upgrade_version=$2
new_pkg=$3

ossec_path="/Library/Ossec"
wazuh_control="$ossec_path/bin/wazuh-control"

log_info() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1"
}

log_error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2
  exit 1
}

is_wazuh_agent_installed() {
  if [ -d "$ossec_path" ]; then
    return 0
  else
    return 1
  fi
}

get_wazuh_version(){
    if [ -f "$wazuh_control" ]; then
        echo "$($wazuh_control info -v)"
    else
        log_error "The script $wazuh_control does not exist."
    fi
}

download_pkg(){
    local url=$1
    local output_file="/tmp/$(basename "$url")"
    curl -o "$output_file" "$url" && echo "$output_file"
}

uninstall_agent(){
    if launchctl list | grep -q "com.wazuh.agent"; then
        launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist
        /bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
    else
        log_info "Wazuh agent service is not currently loaded. Skipping unload."
    fi
    /bin/rm -r "$ossec_path"
    /bin/rm -rf /Library/StartupItems/WAZUH
    /usr/bin/dscl . -delete "/Users/wazuh"
    /usr/bin/dscl . -delete "/Groups/wazuh"
    /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
}

install_agent(){
    local pkg_file=$1

    echo "WAZUH_MANAGER='1.1.1.1'" > /tmp/wazuh_envs && installer -pkg $pkg_file -target / | tee '/tmp/installer.log'
    launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist
    if grep -iqE "The (upgrade|install) was successful" /tmp/installer.log; then
        local version_installed=$(get_wazuh_version)
        log_info "Installed version: $version_installed"
    else
        log_error "The installation could not be completed. The package will not be uploaded.";
    fi
}

start_wazuh_agent(){
    $wazuh_control start
}

main(){
    if [ -z "$old_package_url" ]; then
        log_error "Missing package URL. Usage: $0 <package_url> <expected_version_upgrade>"
    fi

    if [ -z "$new_pkg" ]; then
        log_error "Missing expected upgrade version. Usage: $0 <package_url> <expected_version_upgrade>"
    fi

    old_version=$(download_pkg "$old_package_url" || log_error "Failed to download package.")

    if is_wazuh_agent_installed; then
        version_installed=$(get_wazuh_version)
        log_info "Uninstalling wazuh-agent: $version_installed"
        uninstall_agent
        log_info "Wazuh successfully uninstalled."
    fi

    install_agent $old_version
    start_wazuh_agent

    log_info "Perform upgrade"
    install_agent $new_pkg
    version_installed=$(get_wazuh_version)
    version_installed="${version_installed#v}"
    start_wazuh_agent

    if [ "$version_installed" != "$upgrade_version" ]; then
        log_error "Upgrade version $version_installed does not match expected $upgrade_version"
    fi

    if [ "$(/Library/Ossec/bin/wazuh-control status|grep "is running" -c)" -ne "5" ]; then
        log_error "The service is not running for wazuh version $version_installed"
    fi

    exit 0
}

main
