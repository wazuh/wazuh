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

    mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

    cp ${specs_path}/wazuh-server.spec ${rpm_build_dir}/SPECS/${package_name}.spec

    # Generating source tar.gz
    cd ${build_dir}/server && tar czf "${rpm_build_dir}/SOURCES/${package_name}.tar.gz" "${package_name}"
}

set_debug(){
    local debug="$1"
    if [[ "${debug}" == "no" ]]; then
        echo '%debug_package %{nil}' > /etc/rpm/macros
    fi
}

build_deps(){
    echo "%_source_filedigest_algorithm 8" >> /root/.rpmmacros
    echo "%_binary_filedigest_algorithm 8" >> /root/.rpmmacros
    rpmbuild="/usr/local/bin/rpmbuild"
}

build_package(){
    package_name="$1"
    debug="$2"
    short_commit_hash="$3"
    wazuh_version="$4"

    if [ "${ARCHITECTURE_TARGET}" = "arm64" ]; then
        ARCH="aarch64"
    elif [ "${ARCHITECTURE_TARGET}" = "amd64" ]; then
        ARCH="x86_64"
    else
        echo "Invalid architecture selected. Choose: [arm64, amd64]"
        return 1
    fi

    $rpmbuild --define "_sysconfdir /etc" --define "_topdir ${rpm_build_dir}" \
        --define "_threads ${JOBS}" --define "_release ${REVISION}" --define "_isstage ${IS_STAGE}" \
        --define "_localstatedir ${INSTALLATION_PATH}" --define "_debugenabled ${debug}" \
        --define "_version ${wazuh_version}" --define "_hashcommit ${short_commit_hash}" \
        --target $ARCH -ba ${rpm_build_dir}/SPECS/${package_name}.spec
    return $?
}

get_package_and_checksum(){
    src="$3"
    RPM_NAME=$(ls -R ${rpm_build_dir}/RPMS | grep "wazuh-server" | grep -v "debuginfo")
    SRC_NAME=$(ls -R ${rpm_build_dir}/SRPMS | grep "\.src\.rpm$")
    SYMBOLS_NAME=$(ls -R ${rpm_build_dir}/RPMS)
    SYMBOLS_NAME=$(echo "${SYMBOLS_NAME}" | grep "wazuh-server-debuginfo" || true)

    echo "RPM_NAME: ${RPM_NAME}"
    echo "SYMBOLS_NAME:${SYMBOLS_NAME}"

    if [[ "${checksum}" == "yes" ]]; then
        cd "${rpm_build_dir}/RPMS" && sha512sum $RPM_NAME > /var/local/wazuh/$RPM_NAME.sha512
        if [[ "${src}" == "yes" ]]; then
            cd "${rpm_build_dir}/SRPMS" && sha512sum $SRC_NAME > /var/local/wazuh/$SRC_NAME.sha512
        fi

        if [ -n "${SYMBOLS_NAME}" ]; then
            sha512sum $SYMBOLS_NAME > /var/local/wazuh/$SYMBOLS_NAME.sha512
        fi
    fi

    if [[ "${src}" == "yes" ]]; then
        mv ${rpm_build_dir}/SRPMS/$SRC_NAME /var/local/wazuh
    else
        mv ${rpm_build_dir}/RPMS/$RPM_NAME /var/local/wazuh
        if [ -n "${SYMBOLS_NAME}" ]; then
            mv ${rpm_build_dir}/RPMS/$SYMBOLS_NAME /var/local/wazuh
        fi
    fi
}
