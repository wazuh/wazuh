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

setup_build(){
    sources_dir="$1"
    specs_path="$2"
    build_dir="$3"
    package_name="$4"

    rpm_build_dir=${build_dir}/rpmbuild
    file_name="$package_name-${REVISION}"
    src_file="${file_name}.src.rpm"

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
    short_commit_hash="$3"

    if [ "${ARCHITECTURE_TARGET}" = "i386" ] || [ "${ARCHITECTURE_TARGET}" = "armhf" ]; then
        linux="linux32"
    fi

    if [ "${ARCHITECTURE_TARGET}" = "armhf" ]; then
        ARCH="armv7hl"
    elif [ "${ARCHITECTURE_TARGET}" = "arm64" ]; then
        ARCH="aarch64"
    elif [ "${ARCHITECTURE_TARGET}" = "amd64" ]; then
        ARCH="x86_64"
    elif [[ "${ARCHITECTURE_TARGET}" == "i386" ]] || [[ "${ARCHITECTURE_TARGET}" == "ppc64le" ]]; then
        ARCH=${ARCHITECTURE_TARGET}
    else
        echo "Invalid architecture selected. Choose: [armhf, arm64, amd64, i386, ppc64le]"
        return 1
    fi

    if [[ "${IS_PACKAGE_RELEASE}" == "yes" ]]; then
        rpm_file="${file_name}.${ARCH}.rpm"
    else
        # Replace "-" with "_" between BUILD_TARGET and Version
        base_name="$(sed 's/-/_/2' <<< "$file_name")"
        rpm_file="${base_name}_${ARCH}_${short_commit_hash}.rpm"
    fi

    $linux $rpmbuild --define "_sysconfdir /etc" --define "_topdir ${rpm_build_dir}" \
        --define "_threads ${JOBS}" --define "_release ${REVISION}" \
        --define "_localstatedir ${INSTALLATION_PATH}" --define "_debugenabled ${debug}" \
        --define "_rpmfilename ${rpm_file}" \
        --target $ARCH -ba ${rpm_build_dir}/SPECS/${package_name}.spec
    return 0
}

get_checksum(){
    src="$3"
    if [[ "${checksum}" == "yes" ]]; then
        cd "${rpm_build_dir}/RPMS" && sha512sum ${rpm_file} > /var/local/wazuh/${rpm_file}.sha512
        if [[ "${src}" == "yes" ]]; then
            cd "${rpm_build_dir}/SRPMS" && sha512sum ${src_file} > /var/local/wazuh/${src_file}.sha512
        fi
    fi

    if [[ "${src}" == "yes" ]]; then
        mv ${rpm_build_dir}/SRPMS/${src_file} /var/local/wazuh
    else
        mv ${rpm_build_dir}/RPMS/${rpm_file} /var/local/wazuh
    fi
}
