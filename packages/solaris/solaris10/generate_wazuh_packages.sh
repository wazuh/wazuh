#!/bin/bash
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2015, Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
# Wazuh Solaris 10 Package builder.


# CONFIGURATION VARIABLES
wazuh_branch="$(echo "$2" | cut -d "/" -f2)"
PATH=$PATH:/opt/csw/bin:/usr/sfw/bin
VERSION=""
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
REPOSITORY="https://github.com/wazuh/wazuh"
ARCH=`uname -p`
install_path="/var/ossec"
THREADS=4
PROFILE=agent
deps_version="false"
SOURCE=${CURRENT_PATH}/repository
CONFIG="$SOURCE/etc/preloaded-vars.conf"
target_dir="${CURRENT_PATH}/output"
control_binary=""
short_version=""

trap ctrl_c INT

if [ -z "${wazuh_branch}" ]; then
    wazuh_branch="main"
fi

if [ -z "$ARCH" ]; then
    ARCH="i386"
fi

set_control_binary() {
  if [ -e ${SOURCE}/VERSION.json ]; then
    wazuh_version="v$(sed -n 's/.*"version"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p' ${SOURCE}/VERSION.json)"
    number_version=`echo "${wazuh_version}" | cut -d v -f 2`
    major=`echo $number_version | cut -d . -f 1`
    minor=`echo $number_version | cut -d . -f 2`

    if [ "$major" -le "4" ] && [ "$minor" -le "1" ]; then
        control_binary="ossec-control"
    else
        control_binary="wazuh-control"
    fi
  fi
}

build_environment(){
    echo "Installing dependencies."

    unset CPLUS_INCLUDE_PATH
    unset LD_LIBRARY_PATH
    export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0
    export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib
    export PATH=/usr/sbin:/usr/bin:/usr/ccs/bin:/opt/csw/bin
    mkdir -p /usr/local
    echo "export PATH=/usr/sbin:/usr/bin:/usr/ccs/bin:/opt/csw/bin" >> /etc/profile
    echo "export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0" >> /etc/profile
    echo "export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib" >> /etc/profile

    cd ${CURRENT_PATH}

    # Download and install package manager
    if [ ! -f /opt/csw/bin/pkgutil ]; then
        pkgadd -a ${CURRENT_PATH}/noaskfile -d http://get.opencsw.org/now -n all
    fi

    #Download and install tools
    pkgutil -y -i git
    pkgutil -y -i make
    pkgutil -y -i automake
    pkgutil -y -i autoconf
    pkgutil -y -i libtool
    pkgutil -y -i wget
    pkgutil -y -i curl
    pkgutil -y -i gtar
    pkgutil -y -i gsed
    pkgutil -y -i libisl15
    pkgutil -y -i libmpc3
    pkgutil -y -i binutils
    curl -OL http://mirror.opencsw.org/opencsw/allpkgs/gcc5g%2b%2b-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg.gz
    gunzip -f gcc5g%2b%2b-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg.gz
    pkgadd -a ${CURRENT_PATH}/noaskfile -d gcc5g%2b%2b-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg -n all
    curl -OL http://mirror.opencsw.org/opencsw/allpkgs/gcc5core-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg.gz
    gunzip -f gcc5core-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg.gz
    pkgadd -a ${CURRENT_PATH}/noaskfile -d gcc5core-5.5.0%2cREV%3d2017.10.23-SunOS5.10-sparc-CSW.pkg -n all
    curl -OL http://mirror.opencsw.org/opencsw/allpkgs/gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg.gz
    gunzip -f gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg.gz
    pkgadd -a ${CURRENT_PATH}/noaskfile -d gmake-4.2.1%2cREV%3d2016.08.04-SunOS5.10-sparc-CSW.pkg -n all

    # Install precompiled gcc-5.5
    curl -LO http://packages-dev.wazuh.com/deps/solaris/precompiled-solaris-gcc-5.5.0.tar.gz
    gtar -xzvf precompiled-solaris-gcc-5.5.0.tar.gz > /dev/null
    cd gcc-5.5.0
    gmake install > /dev/null
    cd ..
    rm -rf *gcc-*
    ln -sf /usr/local/gcc-5.5.0/bin/g++ /usr/bin/g++

    # Install precompiled cmake-3.18.3
    curl -LO http://packages-dev.wazuh.com/deps/solaris/precompiled-solaris-cmake-3.18.3.tar.gz
    gtar -xzvf precompiled-solaris-cmake-3.18.3.tar.gz > /dev/null
    cd cmake-3.18.3
    gmake install > /dev/null
    cd ..
    rm -rf *cmake-*
    ln -sf /usr/local/bin/cmake /usr/bin/cmake

    # Download and install perl5.10
    perl_version=`perl -v | cut -d . -f2 -s | head -n1`

    if [[ $perl_version == "10" ]]; then
        echo " Perl 5.10.1 already installed"
    else
        wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz
        gunzip ./perl-5.10.1.tar.gz > /dev/null
        tar xvf perl-5.10.1.tar > /dev/null
        cd perl-5.10.1
        ./Configure -Dcc=gcc -d -e -s > /dev/null
        gmake clean > /dev/null
        gmake -d -s > /dev/null
        gmake install -d -s > /dev/null
        cd ..

        # Remove old version of perl and replace it with perl5.10.1
        rm /usr/bin/perl
        mv /opt/csw/bin/perl5.10.1 /usr/bin/
        mv /usr/bin/perl5.10.1 /usr/bin/perl

        # Remove perl code
        rm -rf perl-5.10.1*
    fi
}


config(){
    echo USER_LANGUAGE="en" > $CONFIG
    echo USER_NO_STOP="y" >> $CONFIG
    echo USER_INSTALL_TYPE="agent" >> $CONFIG
    echo USER_DIR=${install_path} >> $CONFIG
    echo USER_DELETE_DIR="y" >> $CONFIG
    echo USER_CLEANINSTALL="y" >> $CONFIG
    echo USER_BINARYINSTALL="y" >> $CONFIG
    echo USER_AGENT_SERVER_IP="MANAGER_IP" >> $CONFIG
    echo USER_ENABLE_SYSCHECK="y" >> $CONFIG
    echo USER_ENABLE_ROOTCHECK="y" >> $CONFIG
    echo USER_ENABLE_ACTIVE_RESPONSE="y" >> $CONFIG
    echo USER_CA_STORE="/path/to/my_cert.pem" >> $CONFIG
}

check_version(){
    number_version=`echo "$VERSION" | cut -d v -f 2`
    major=`echo $number_version | cut -d . -f 1`
    minor=`echo $number_version | cut -d . -f 2`
    if [ "$major" -eq 3 ]; then
        if [ "$minor" -ge 5 ]; then
            deps_version="true"
        fi
    elif [ "$major" -gt 3 ]; then
        deps_version="true"
    fi
    short_version="${major}.${minor}"
}

installation(){
    export PATH=/usr/local/gcc-5.5.0/bin:/usr/sbin:/usr/bin:/usr/ccs/bin:/opt/csw/bin
    export CPLUS_INCLUDE_PATH=/usr/local/gcc-5.5.0/include/c++/5.5.0
    export LD_LIBRARY_PATH=/usr/local/gcc-5.5.0/lib

    cd $SOURCE/src
    gmake clean
    check_version
    if [ "$deps_version" = "true" ]; then
        gmake deps TARGET=agent
    fi
    arch="$(uname -p)"
    # Build the binaries
    if [ "$arch" = "sparc" ]; then
        gmake -j $THREADS TARGET=agent USE_SELINUX=no USE_BIG_ENDIAN=yes || return 1
    else
        gmake -j $THREADS TARGET=agent USE_SELINUX=no || return 1
    fi

    cd $SOURCE

    # Patch solaris 10 sh files to change the shebang
    for file in $(find . -name "*.sh");do
        sed 's:#!/bin/sh:#!/usr/xpg4/bin/sh:g' $file > $file.new
        mv $file.new $file && chmod +x $file
    done

    config
    /bin/bash $SOURCE/install.sh || return 1
    cd ${CURRENT_PATH}
}

compute_version_revision()
{
    wazuh_version="$(sed -n 's/.*"version"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p' ${SOURCE}/VERSION.json)"
    revision=$(sed -n 's/.*"stage": *"\([^"]*\)".*/\1/p' ${SOURCE}/VERSION.json)

    echo $wazuh_version > /tmp/VERSION
    echo $revision > /tmp/REVISION

    pushd ${SOURCE}
    short_commit_hash="$(git rev-parse --short=7 HEAD)"

    /usr/bin/nawk -v commit="$short_commit_hash" '
    {
        lines[NR] = $0  # Store lines in an array
    }
    END {
        last_index = NR  # Save the last line index
        for (i = 1; i <= last_index; i++) {
            if (i == last_index) {  # When reaching the last line (assumed to be "}")
                if (lines[i-1] !~ /,$/)  # If the previous line does not end with a comma, add one
                    lines[i-1] = lines[i-1] ",";

                print lines[i-1];  # Print the modified previous line
                print "    \"commit\": \"" commit "\"";  # Insert commit using the passed variable
                print lines[i];  # Print the closing brace
            } else if (i < last_index - 1) {
                print lines[i];  # Print all other lines unchanged
            }
        }
    }
    ' VERSION.json > VERSION.json.tmp && mv VERSION.json.tmp VERSION.json

    # Remove the temporary file after processing (if any remains)
    [ -f VERSION.json.tmp ] && rm VERSION.json.tmp

    cat VERSION.json
    popd

    return 0
}

clone(){
    cd ${CURRENT_PATH}
    git clone --depth=1 $REPOSITORY -b $wazuh_branch ${SOURCE} || return 1
    cd $SOURCE
    compute_version_revision

    return 0
}

package(){
    cd ${CURRENT_PATH}
    find ${install_path} | awk 'length > 0' > "wazuh-agent_$VERSION.list"
    ver=`echo $VERSION | cut -d'v' -f 2`
    sed  "s:expected_platform=\".*\":expected_platform=\"$ARCH\":g" checkinstall.sh > checkinstall.sh.new && mv checkinstall.sh.new checkinstall.sh
    sed  "s:ARCH=\".*\":ARCH=\"$ARCH\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    sed  "s:ARCH=\".*\":ARCH=\"$ARCH\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    sed  "s:VERSION=\".*\":VERSION=\"$ver\":g" pkginfo > pkginfo.new && mv pkginfo.new pkginfo
    echo "i pkginfo=pkginfo" > "wazuh-agent_$VERSION.proto"
    echo "i checkinstall=checkinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i preinstall=preinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i postinstall=postinstall.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i preremove=preremove.sh" >> "wazuh-agent_$VERSION.proto"
    echo "i postremove=postremove.sh" >> "wazuh-agent_$VERSION.proto"
    echo "f none /etc/init.d/wazuh-agent  0755 root root" >> "wazuh-agent_$VERSION.proto"
    echo "s none /etc/rc2.d/S97wazuh-agent=/etc/init.d/wazuh-agent" >> "wazuh-agent_$VERSION.proto"
    echo "s none /etc/rc3.d/S97wazuh-agent=/etc/init.d/wazuh-agent" >> "wazuh-agent_$VERSION.proto"
    cat "wazuh-agent_$VERSION.list" | pkgproto >> "wazuh-agent_$VERSION.proto"

    echo $VERSION
    pkgmk -o -r / -d . -f "wazuh-agent_$VERSION.proto"
    pkg_name="wazuh-agent_$VERSION-sol10-$ARCH.pkg"
    pkgtrans -s ${CURRENT_PATH} "${pkg_name}" wazuh-agent

    mkdir -p ${target_dir}

    mv -f ${pkg_name} ${target_dir}

    if [ "${compute_checksums}" = "yes" ]; then
        cd ${target_dir} && /opt/csw/gnu/sha512sum "${pkg_name}" > "${checksum_dir}/${pkg_name}.sha512"
    fi
}

clean(){
    set_control_binary
    cd ${CURRENT_PATH}
    rm -rf ${SOURCE}
    rm -rf wazuh-agent wazuh *.list *proto
    rm -f *.new

    ## Stop and remove application
    if [ ! -z $control_binary ]; then
        ${install_path}/bin/${control_binary} stop
    fi

    rm -r ${install_path}*

    # remove launchdaemons
    rm -f /etc/init.d/wazuh-agent
    rm -f /etc/rc2.d/S97wazuh-agent
    rm -f /etc/rc3.d/S97wazuh-agent

    ## Remove User and Groups
    userdel wazuh
    groupdel wazuh
}

ctrl_c() {
    clean 1
}

build(){

    cd ${CURRENT_PATH}

    VERSION="v$(sed -n 's/.*"version"[ \t]*:[ \t]*"\([^"]*\)".*/\1/p' ${SOURCE}/VERSION.json)"
    echo "------------"
    echo "| Building |"
    echo "------------"

    groupadd wazuh
    useradd -g wazuh wazuh
    installation
    package
}


show_help() {
    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename $0) - Generate a Solaris 10 package"
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename $0) [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -b, --branch <branch>"
    echo -e "                Select Git branch or tag e.g. ${wazuh_branch}."
    echo -e ""
    echo -e "        -c, --checksum"
    echo -e "                Compute the SHA512 checksum of the package."
    echo -e ""
    echo -e "        -e, --environment"
    echo -e "                Install all the packages necessaries to build the package."
    echo -e ""
    echo -e "        -h, --help"
    echo -e "                Shows this help."
    echo -e ""
    echo -e "        -p, --install-path <pkg_home>"
    echo -e "                Installation path for the package. By default: /var."
    echo -e ""
    echo -e "        -s, --store  <pkg_directory>"
    echo -e "                Directory to store the resulting package. By default, an output folder will be created."
    echo -e ""
    exit $1
}

build_package(){
    clone || return 1
    build || return 1

    return 0
}

# Main function, processes user input
main() {
  # If the script is called without arguments
  # show the help
  if [[ -z $1 ]] ; then
    show_help 0
  fi

  build_env="no"
  build_pkg="no"

  while [ -n "$1" ]
  do
    case $1 in
        "-b"|"--branch")
            if [ -n "$2" ]
            then
                wazuh_branch="$2"
                build_pkg="yes"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-h"|"--help")
            show_help
            exit 0
        ;;
        "-e"|"-u"|"--environment" )
            build_environment
            exit 0
        ;;
        "-p"|"--install-path")
            if [ -n "$2" ]
            then
                install_path="$2"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-s"|"--store")
            if [ -n "$2" ]
            then
                target_dir="$2"
                shift 2
            else
                show_help 1
            fi
        ;;
        "-c" | "--checksum")
            if [ -n "$2" ]; then
                checksum_dir="$2"
                compute_checksums="yes"
                shift 2
            else
                compute_checksums="yes"
                shift 1
            fi
        ;;
        *)
          show_help 1
    esac
  done

  if [[ "${build_env}" = "yes" ]]; then
    build_environment || exit 1
  fi

  if [ -z "${checksum_dir}" ]; then
    checksum_dir="${target_dir}"
  fi

  if [[ "${build_pkg}" = "yes" ]]; then
    build_package || clean 1
  fi

  clean 0

  return 0
}

main "$@"
