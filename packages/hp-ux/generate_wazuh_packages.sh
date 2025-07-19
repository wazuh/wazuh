#!/bin/sh
# Created by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2018 Wazuh Inc.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2
# Wazuh HP-UX Package builder.

set -x

current_path="$( cd $(dirname $0) ; pwd -P )"
install_path="/var/ossec"
build_tools_path="/home/okkam"
source_directory=/wazuh-sources
configuration_file="${source_directory}/etc/preloaded-vars.conf"
target_dir="${current_path}/output/"
wazuh_version=""
wazuh_revision=""
depot_path=""
control_binary=""
compute_checksums="no"

# Needed variables to build Wazuh with custom GCC and cmake
PATH=${build_tools_path}/bootstrap-gcc/gcc94_prefix/bin:${build_tools_path}/cmake_prefix_install/bin:/usr/local/bin:$PATH
LD_LIBRARY_PATH=${build_tools_path}/bootstrap-gcc/gcc94_prefix/lib:${build_tools_path}/bootstrap-gcc/gcc94_prefix/lib/hpux64
export LD_LIBRARY_PATH
export PATH
CXX=${build_tools_path}/bootstrap-gcc/gcc94_prefix/bin/g++

build_environment() {

    # Resizing partitions for Site Ox boxes (used by Wazuh team)
    if grep 'siteox.com' /etc/motd > /dev/null 2>&1; then
        for partition in "/home" "/tmp"; do
            partition_size=$(df -b | grep $partition | awk -F' ' '{print $5}')
            if [[ ${partition_size} -lt "3145728" ]]; then
                echo "Resizing $partition partition to 3GB"
                volume=$(cat /etc/fstab | grep $partition | awk -F' ' '{print $1}')
                lvextend -L 3000 $volume
                fsadm -b 3072000 $partition > /dev/null 2>&1
          fi
      done
    fi

    echo "Installing dependencies."
    depot=""
    if [ -z "${depot_path}" ]
    then
        depot=${current_path}/depothelper-2.20-ia64_64-11.31.depot
    else
        depot=$depot_path
    fi

    #Install dependencies
    swinstall -s $depot \*
    /usr/local/bin/depothelper curl unzip make bash gzip automake autoconf libtool coreutils gdb perl regex python

    rm -rf ${build_tools_path}

    # Install GCC 9.4
    mkdir ${build_tools_path}
    cd ${build_tools_path}
    mkdir bootstrap-gcc
    cd ${build_tools_path}/bootstrap-gcc
    curl -k -SO http://packages.wazuh.com/utils/gcc/gcc_9.4_HPUX_build.tar.gz
    gunzip gcc_9.4_HPUX_build.tar.gz
    tar -xf gcc_9.4_HPUX_build.tar
    rm -f gcc_9.4_HPUX_build.tar
    cp -f ${build_tools_path}/bootstrap-gcc/gcc94_prefix/bin/gcc ${build_tools_path}/bootstrap-gcc/gcc94_prefix/bin/cc

    # Install cmake 3.22.2
    cd ${build_tools_path}
    curl -k -SO http://packages.wazuh.com/utils/cmake/cmake_3.22.2_HPUX_build.tar.gz
    gunzip cmake_3.22.2_HPUX_build.tar.gz
    tar -xf cmake_3.22.2_HPUX_build.tar
    rm -f cmake_3.22.2_HPUX_build.tar
}

config() {
    echo USER_LANGUAGE="en" > ${configuration_file}
    echo USER_NO_STOP="y" >> ${configuration_file}
    echo USER_INSTALL_TYPE="agent" >> ${configuration_file}
    echo USER_DIR=${install_path} >> ${configuration_file}
    echo USER_DELETE_DIR="y" >> ${configuration_file}
    echo USER_CLEANINSTALL="y" >> ${configuration_file}
    echo USER_BINARYINSTALL="y" >> ${configuration_file}
    echo USER_AGENT_SERVER_IP="MANAGER_IP" >> ${configuration_file}
    echo USER_ENABLE_SYSCHECK="y" >> ${configuration_file}
    echo USER_ENABLE_ROOTCHECK="y" >> ${configuration_file}
    echo USER_ENABLE_ACTIVE_RESPONSE="y" >> ${configuration_file}
    echo USER_CA_STORE="n" >> ${configuration_file}
}

compute_version_revision() {
    wazuh_version="$(awk -F'"' '/"version"[ \t]*:/ {print $4}' $source_directory/VERSION.json)"

    if [ -z "$wazuh_revision" ]; then
        stage_value=$(awk -F'"' '/"stage"[ \t]*:/ {print $4}' $source_directory/VERSION.json)
        wazuh_revision=$(echo "$stage_value" | sed 's/[^0-9]*\([0-9][0-9]*\).*/\1/')
    fi

    # Add commit hash to the VERSION.json file
    short_commit_hash=$(/usr/local/bin/curl -ks "https://api.github.com/repos/wazuh/wazuh/commits/${wazuh_branch}" | awk -F '"' '/"sha":/ {print substr($4, 1, 7); exit}')
    awk -v commit="$short_commit_hash" '
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
    ' $source_directory/VERSION.json > $source_directory/VERSION.json.tmp && mv $source_directory/VERSION.json.tmp $source_directory/VERSION.json
    cat $source_directory/VERSION.json

    # Remove the temporary file after processing (if any remains)
    [ -f $source_directory/VERSION.json.tmp ] && rm $source_directory/VERSION.json.tmp

    echo ${wazuh_version} > /tmp/VERSION
    echo ${wazuh_revision} > /tmp/REVISION

    return 0
}

download_source() {
    echo " Downloading source"
    /usr/local/bin/curl -k -L -o "/wazuh.zip" "https://github.com/wazuh/wazuh/archive/${wazuh_branch}.zip"
    /usr/local/bin/unzip /wazuh.zip
    mv wazuh-* ${source_directory}
    compute_version_revision
}

check_version() {
    wazuh_version="v$(awk -F'"' '/"version"[ \t]*:/ {print $4}' $source_directory/VERSION.json)"
    number_version=`echo "${wazuh_version}" | cut -d v -f 2`
    major=`echo $number_version | cut -d . -f 1`
    minor=`echo $number_version | cut -d . -f 2`
    deps_version=`cat ${source_directory}/src/Makefile | grep "DEPS_VERSION =" | cut -d " " -f 3`
}

compile() {
    echo "Compiling code"
    # Compile and install wazuh
    cd ${source_directory}/src
    config
    check_version
    gmake deps RESOURCES_URL=http://packages.wazuh.com/deps/${deps_version} TARGET=agent
    gmake TARGET=agent USE_SELINUX=no
    bash ${source_directory}/install.sh || { echo "install.sh failed! Aborting." >&2; exit 1; }
    # Install std libs needed to run the agent
    cp -f ${build_tools_path}/bootstrap-gcc/gcc94_prefix/lib/libstdc++.so.6.28 ${install_path}/lib
    cp -f ${build_tools_path}/bootstrap-gcc/gcc94_prefix/lib/libgcc_s.so.0 ${install_path}/lib
    ln -s ${install_path}/lib/libstdc++.so.6.28 ${install_path}/lib/libstdc++.so.6
    ln -s ${install_path}/lib/libstdc++.so.6.28 ${install_path}/lib/libstdc++.so
    ln -s ${install_path}/lib/libgcc_s.so.0 ${install_path}/lib/libgcc_s.so
}

create_package() {
    echo "Creating package"

    if [ ! -d ${target_dir} ]; then
        mkdir -p ${target_dir}
    fi

    #Build package
    VERSION=`cat /tmp/VERSION`
    wazuh_version=`echo "${wazuh_version}" | cut -d v -f 2`
    pkg_tar_file="wazuh-agent-${wazuh_version}-${wazuh_revision}-hpux-11v3-ia64.tar"
    tar cvpf ${target_dir}/${pkg_tar_file} ${install_path} /sbin/init.d/wazuh-agent /sbin/rc2.d/S97wazuh-agent /sbin/rc3.d/S97wazuh-agent
    pkg_name="${pkg_tar_file}.gz"
    gzip ${target_dir}/${pkg_tar_file}

    if [ "${compute_checksums}" = "yes" ]; then
        cd ${target_dir}
        pkg_checksum="$(openssl dgst -sha512 ${pkg_name} | cut -d' ' -f "2")"
        echo "${pkg_checksum}  ${pkg_name}" > ${target_dir}/${pkg_name}.sha512
    fi
}

set_control_binary() {
    if [ -e ${source_directory}/VERSION.json ]; then
        wazuh_version="v$(awk -F'"' '/"version"[ \t]*:/ {print $4}' ${source_directory}/VERSION.json)"
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

# Uninstall agent.

clean() {
    exit_code=$1
    set_control_binary

    if [ ! -z $control_binary ]; then
        ${install_path}/bin/${control_binary} stop
    fi

    rm -rf ${install_path}

    find /sbin -name "*wazuh-agent*" -exec rm {} \;
    userdel wazuh
    groupdel wazuh

    exit ${exit_code}
}

show_help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -e Install all the packages necessaries to build the package"
    echo "    -b <branch> Select Git branch. Example v3.5.0"
    echo "    -s <pkg_directory> Directory to store the resulting package. By default, an output folder will be created."
    echo "    -p <pkg_home> Installation path for the package. By default: /var"
    echo "    -c, --checksum Compute the SHA512 checksum of the package."
    echo "    -r, --revision Revision to naming Wazuh agent package."
    echo "    -d <path_to_depot>, --depot Change the path to depothelper package (by default current path)."
    echo "    -h Shows this help"
    echo
    exit $1
}

build_package() {
    download_source
    compile
    create_package
    clean 0
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
            "-b")
                if [ -n "$2" ]
                    then
                    wazuh_branch="$2"
                    build_pkg="yes"
                    shift 2
                else
                    show_help 1
                fi
            ;;
            "-h")
                show_help
                exit 0
            ;;
            "-e")
                build_env="yes"
                shift 1
            ;;
            "-p")
                if [ -n "$2" ]
                    then
                    install_path="$2"
                    shift 2
                else
                    show_help 1
                fi
            ;;
            "-s")
                if [ -n "$2" ]
                    then
                    target_dir="$2"
                    shift 2
                else
                    show_help 1
                fi
            ;;
            "-c" | "--checksum")
                compute_checksums="yes"
                shift 1
            ;;
            "-d")
                if [ -n "$2" ]
                    then
                    depot_path="$2"
                    shift 2
                else
                    show_help 1
                fi
            ;;
            "-r"|"--revision")
                if [ -n "$2" ]; then
                    wazuh_revision="$2"
                    shift 2
                else
                    show_help 1
                fi
            ;;
            *)
                show_help 1
        esac
    done

    if [[ "${build_env}" = "yes" ]]; then
        build_environment || exit 1
        exit 0
    fi

    if [[ "${build_pkg}" = "yes" ]]; then
        build_package || clean 1
    fi

    return 0
}

main "$@"
