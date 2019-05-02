#!/bin/bash
# install wazuh server
# Wazuh documentation - https://documentation.wazuh.com/current/installation-guide/installing-wazuh-server/index.html
#######################################

# Versions to install
WAZUH_MANAGER_PKG="wazuh-manager"
WAZUH_API_PKG="wazuh-api"

# Configuration variables
PKG_MANAGER=""
PKG_INSTALL=""
PKG_OPTIONS=""
OS_FAMILY=""
REPO_FILE=""
SOURCE_INSTALL=0

# Variables from command line
INSTALL_TYPE=${1:-stable}
BRANCH=${2:-master}
PACKAGE_VERSION=$3

set_global_parameters() {
    echo "Received arguments: Install type: ${INSTALL_TYPE}. Branch: ${BRANCH}. Package version: ${PACKAGE_VERSION}."
    if command -v apt-get > /dev/null 2>&1 ; then
        PKG_MANAGER="apt-get"
        PKG_OPTIONS="-y"
        OS_FAMILY="Debian"
        REPO_FILE="/etc/apt/sources.list.d/wazuh.list"
        if [ ! -z "$PACKAGE_VERSION" ]; then
            WAZUH_MANAGER_PKG="${WAZUH_MANAGER_PKG}=${PACKAGE_VERSION}"
            WAZUH_API_PKG="${WAZUH_API_PKG}=${PACKAGE_VERSION}"
        fi

    elif command -v yum > /dev/null 2>&1 ; then
        PKG_MANAGER="yum"
        PKG_OPTIONS="-y -q -e 0"
        OS_FAMILY="RHEL"
        REPO_FILE="/etc/yum.repos.d/wazuh.repo"
        if [ ! -z "$PACKAGE_VERSION" ]; then
            WAZUH_MANAGER_PKG="${WAZUH_MANAGER_PKG}-${PACKAGE_VERSION}"
            WAZUH_API_PKG="${WAZUH_API_PKG}-${PACKAGE_VERSION}"
        fi
    elif command -v zypper > /dev/null 2>&1 ; then
        PKG_MANAGER="zypper"
        PKG_OPTIONS="-y -l"
        OS_FAMILY="SUSE"
        REPO_FILE="/etc/zypp/repos.d/wazuh.repo"
        if [ ! -z "$PACKAGE_VERSION" ]; then
            WAZUH_MANAGER_PKG="${WAZUH_MANAGER_PKG}-${PACKAGE_VERSION}"
            WAZUH_API_PKG="${WAZUH_API_PKG}-${PACKAGE_VERSION}"
        fi
    fi

    PKG_INSTALL="${PKG_MANAGER} install"

    return 0
}

install_dependencies() {
    ## RHEL/CentOS/Fedora/Amazon/SUSE based OS
    if [ "${OS_FAMILY}" == "RHEL" ] || [ "${OS_FAMILY}" == "SUSE" ]; then
        ${PKG_INSTALL} ${PKG_OPTIONS} openssl wget which
    ## Debian/Ubuntu based OS
    else
        ${PKG_MANAGER} update
        ${PKG_INSTALL} ${PKG_OPTIONS} curl apt-transport-https lsb-release \
        openssl software-properties-common dirmngr
    fi
}

add_nodejs_repository() {
  if [ "${OS_FAMILY}" == "RHEL" ]; then
    curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
  elif [ "${OS_FAMILY}" == "SUSE" ]; then
    ${PKG_MANAGER} addrepo http://download.opensuse.org/distribution/leap/15.0/repo/oss/ node8
    ${PKG_MANAGER} --gpg-auto-import-keys refresh
  else
    curl -sL https://deb.nodesource.com/setup_8.x | bash -
  fi
}

add_wazuh_stable_repository() {
    # Add Wazuh Repository
    ## RHEL/CentOS/Fedora/Amazon/SUSE based OS
    if [ "${OS_FAMILY}" == "RHEL" ] || [ "${OS_FAMILY}" == "SUSE" ]; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        echo -ne "[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh epository\nbaseurl=https://packages.wazuh.com/3.x/yum/\nprotect=1" > ${REPO_FILE}

    ## Debian/Ubuntu based OS
    else
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a ${REPO_FILE}
        ${PKG_MANAGER} update
    fi
}

add_wazuh_pre_release_repository() {
    # Add Wazuh Repository
    ## RHEL/CentOS/Fedora/Amazon/SUSE based OS
    if [ "${OS_FAMILY}" == "RHEL" ] || [ "${OS_FAMILY}" == "SUSE" ]; then
        rpm --import https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH
        echo -ne "[wazuh_pre_release]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/yum/\nprotect=1" > ${REPO_FILE}

    ## Debian/Ubuntu based OS
    else
        curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a ${REPO_FILE}
        ${PKG_MANAGER} update
    fi
}

add_wazuh_repository() {
    case "$INSTALL_TYPE" in
    stable)
        echo "Installing from stable repositories"
        add_wazuh_stable_repository
        ;;
    pre_release)
        echo "Installing from pre release repositories"
        add_wazuh_pre_release_repository
        ;;
    sources)
        echo "Installing from sources"
        SOURCE_INSTALL=1
        ;;
    *)
        echo "Install type not valid: ${INSTALL_TYPE}. Valid ones are stable, pre_release and sources."
        exit 1
    ;;
    esac
}

install_wazuh_from_packages() {
    # Install the Wazuh Manager and enable integrator module
    ${PKG_INSTALL} ${PKG_OPTIONS} ${WAZUH_MANAGER_PKG}
    # The auth module only needs to be enabled in
    # versions prior to v3.8.0
    . /etc/ossec-init.conf
    if [[ ${VERSION} < "v3.8.0" ]]; then
        echo "Version inferior to v3.8.0"
        /var/ossec/bin/ossec-control enable auth
    fi
    if [[ ${VERSION} < "v3.9.0" ]]; then
        echo "Version inferior to v3.9.0"
        ${PKG_INSTALL} ${PKG_OPTIONS} python-cryptography python-setuptools
    fi
    if [[ ${VERSION} < "v4.0.0" ]]; then
        echo "Version inferior to v4.0.0"
        # Install NodeJS and Wazuh API
        ${PKG_INSTALL} ${PKG_OPTIONS} nodejs
        ${PKG_INSTALL} ${PKG_OPTIONS} ${WAZUH_API_PKG}
    fi
}

install_wazuh_from_sources() {
    ${PKG_INSTALL} ${PKG_OPTIONS} git make automake autoconf libtool
    git clone https://github.com/wazuh/wazuh -b $BRANCH
    cd wazuh
    cat <<EOT >> etc/preloaded-vars.conf
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="server"
USER_DIR="/var/ossec"
USER_ENABLE_EMAIL="n"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="y"
USER_ENABLE_OPENSCAP="y"
USER_WHITE_LIST="n"
USER_ENABLE_SYSLOG="y"
USER_ENABLE_AUTHD="y"
USER_AUTO_START="y"
EOT
    ./install.sh
    cd ..

    . /etc/ossec-init.conf
    if [[ ${VERSION} < "v3.8.0" ]]; then
        echo "Version inferior to v3.8.0"
        /var/ossec/bin/ossec-control enable auth
    fi
    if [[ ${VERSION} < "v3.9.0" ]]; then
        echo "Version inferior to v3.9.0"
        ${PKG_INSTALL} ${PKG_OPTIONS} python-cryptography python-setuptools
    fi
    # if [[ ${VERSION} < "v4.0.0" ]]; then
    if [[ ! -d "${DIRECTORY}/api" ]]; then
        echo "Version inferior to v4.0.0"
        # Install NodeJS and Wazuh API
        git clone https://github.com/wazuh/wazuh-api -b $BRANCH
        cd wazuh-api
        ${PKG_INSTALL} ${PKG_OPTIONS} nodejs
        npm config set user 0
        ./install_api.sh
    fi
}

install_wazuh() {
    if [ $SOURCE_INSTALL == 0 ]; then
        install_wazuh_from_packages
    else
        install_wazuh_from_sources
    fi
}

main() {
    set_global_parameters
    install_dependencies
    add_nodejs_repository
    add_wazuh_repository
    install_wazuh
}

main
