#!/bin/bash

# RPM helper functions

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

rpmbuild="rpmbuild"
rpm_build_dir="" # To be define on setup_build

# LEGACY_RPM_AGENT_X86_BUILDER_DOCKERFILE="${CURRENT_PATH}/CentOS/5/x86_64"
# LEGACY_TAR_FILE="${LEGACY_RPM_BUILDER_DOCKERFILE}/i386/centos-5-i386.tar.gz"


setup_build(){
    sources_dir="$1"
    specs_path="$2"
    build_dir="$3"
    package_name="$4"
    # "$5": Debug argument is not used
    short_commit_hash="$6"

    rpm_build_dir=${build_dir}/rpmbuild
    file_name="$package_name-${PACKAGE_RELEASE}"
    # Replace "-" with "_" between BUILD_TARGET and Version
    base_name=$(sed 's/-/_/2' <<< "$package_name")
    rpm_file="${base_name}_${ARCHITECTURE_TARGET}_${short_commit_hash}.rpm"
    src_file="${file_name}.src.rpm"
    extract_path="${rpm_build_dir}/RPMS"
    src_path="${rpm_build_dir}/SRPMS"

    mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

    cp ${specs_path}/wazuh-${BUILD_TARGET}.spec ${rpm_build_dir}/SPECS/${package_name}.spec

    # Generating source tar.gz
    cd ${build_dir}/${BUILD_TARGET} && tar czf "${rpm_build_dir}/SOURCES/${package_name}.tar.gz" "${package_name}"

}

set_debug(){
    local debug="$1"
    if [[ "${debug}" == "no" ]]; then
        echo '%debug_package %{nil}' > /etc/rpm/macros
    fi

}

build_deps(){
    local legacy="$1"
    if [ "${legacy}" = "no" ]; then
        echo "%_source_filedigest_algorithm 8" >> /root/.rpmmacros
        echo "%_binary_filedigest_algorithm 8" >> /root/.rpmmacros
        if [ "${BUILD_TARGET}" = "agent" ]; then
            echo " %rhel 6" >> /root/.rpmmacros
            echo " %centos 6" >> /root/.rpmmacros
            echo " %centos_ver 6" >> /root/.rpmmacros
            echo " %dist .el6" >> /root/.rpmmacros
            echo " %el6 1" >> /root/.rpmmacros
        fi
        rpmbuild="/usr/local/bin/rpmbuild"
    fi
}

build_package(){
    package_name="$1"
    debug="$2"

    if [ "${ARCHITECTURE_TARGET}" = "i386" ] || [ "${ARCHITECTURE_TARGET}" = "armv7hl" ]; then
        linux="linux32"
    fi

    $linux $rpmbuild --define "_sysconfdir /etc" --define "_topdir ${rpm_build_dir}" \
        --define "_threads ${JOBS}" --define "_release ${PACKAGE_RELEASE}" \
        --define "_localstatedir ${INSTALLATION_PATH}" --define "_debugenabled ${debug}" \
        --define "_rpmfilename ${rpm_file}" --target ${ARCHITECTURE_TARGET} \
        -ba ${rpm_build_dir}/SPECS/${package_name}.spec

}

get_checksum(){
    if [[ "${checksum}" == "yes" ]]; then
        cd ${extract_path} && sha512sum ${rpm_file} > /var/local/checksum/${rpm_file}.sha512
        if [[ "${src}" == "yes" ]]; then
            cd ${src_path} && sha512sum ${src_file} > /var/local/checksum/${src_file}.sha512
        fi
    fi

    if [[ "${src}" == "yes" ]]; then
        extract_path="${rpm_build_dir}"
    fi
    find ${extract_path} -maxdepth 3 -type f -name "${file_name}*" -exec mv {} /var/local/wazuh \;
}
