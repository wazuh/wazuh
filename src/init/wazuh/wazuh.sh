#!/bin/sh
# Install functions for Wazuh
# Wazuh.com (https://github.com/wazuh)

patch_version(){
        rm -rf $DIRECTORY/etc/shared/ssh > /dev/null 2>&1
}
WazuhSetup(){
    patch_version
}

WazuhUpgrade()
{
    # Encode Agentd passlist if not encoded

    passlist=$DIRECTORY/agentless/.passlist

    if [ -f $passlist ] && ! base64 -d $passlist > /dev/null 2>&1; then
        cp $passlist $passlist.bak
        base64 $passlist.bak > $passlist

        if [ $? = 0 ]; then
            echo "Agentless passlist encoded successfully."
            rm -f $passlist.bak
        else
            echo "ERROR: Couldn't encode Agentless passlist."
            mv $passlist.bak $passlist
        fi
    fi

    # Remove existing SQLite databases

    rm -f $DIRECTORY/var/db/global.db*
    rm -f $DIRECTORY/var/db/.profile.db*
    rm -f $DIRECTORY/var/db/.template.db*
    rm -f $DIRECTORY/var/db/agents/*

    # Remove existing SQLite databases for Wazuh DB

    rm -f $DIRECTORY/queue/db/*.db*
    rm -f $DIRECTORY/queue/db/.template.db

    #Copy links for libcurl in chroot mode
    PATH=$PATH:/lib:/usr/lib:/usr/lib64:/lib/x86_64-linux-gnu:/lib64
    var_libnss_file=$(whereis libnss_files.so.2 | cut -d ' ' -f 2)
    var_get_dir=${var_libnss_file%libnss_files.so.2}
    var_get_libnss_file=$(echo ${var_get_dir} | cut -d '/' -f2-)

    if [ $(echo ${var_get_libnss_file} | cut -c1-1) != "l" ] ; then
        var_get_libnss_file=$(echo ${var_get_dir} | cut -d '/' -f3-)
    fi

    mkdir -p $DIRECTORY/${var_get_libnss_file}
    ${INSTALL} -m 0770 -o root -g root ${var_get_dir}libnss_files.so.2 ${DIRECTORY}/${var_get_libnss_file}libnss_files.so.2
    ${INSTALL} -m 0770 -o root -g root ${var_get_dir}libnss_dns.so.2 ${DIRECTORY}/${var_get_libnss_file}libnss_dns.so.2
    ${INSTALL} -m 0770 -o root -g root ${var_get_dir}libresolv.so.2 ${DIRECTORY}/${var_get_libnss_file}libresolv.so.2

    #Check if resolv.conf is a regular file or symb link
    if [ -L "/etc/resolv.conf" ]; then
        cp /etc/resolv.conf ${DIRECTORY}/etc/resolv.conf > /dev/null 2>&1
    else
        ln /etc/resolv.conf ${DIRECTORY}/etc/resolv.conf > /dev/null 2>&1
    fi

    #Check if we are on a CentOS platform we need to copy additional files
    if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
        #Search for libnsspem.so
        var_libnsspem_file=$(whereis libnsspem.so | cut -d ' ' -f 2)
        var_get_dir_pem=${var_libnsspem_file%libnsspem.so}
        var_get_libnsspem_file=$(echo ${var_get_dir_pem} | cut -d '/' -f2-)

        if [ $(echo ${var_get_libnsspem_file} | cut -c1-1) != "l" ] ; then
                var_get_libnsspem_file=$(echo ${var_get_dir_pem} | cut -d '/' -f3-)
        fi

	    ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libnssdbm3.so ${DIRECTORY}/${var_get_libnsspem_file}libnssdbm3.so
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libfreeblpriv3.so ${DIRECTORY}/${var_get_libnsspem_file}libfreeblpriv3.so
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libnsspem.so ${DIRECTORY}/${var_get_libnsspem_file}libnsspem.so
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libnsssysinit.so ${DIRECTORY}/${var_get_libnsspem_file}libnsssysinit.so
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libsoftokn3.so ${DIRECTORY}/${var_get_libnsspem_file}libsoftokn3.so
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libsqlite3.so.0 ${DIRECTORY}/${var_get_libnsspem_file}libsqlite3.so.0
        ${INSTALL} -m 0770 -o root -g root ${var_get_dir_pem}libsqlite3.so.0.8.6 ${DIRECTORY}/${var_get_libnsspem_file}libsqlite3.so.0.8.6

        mkdir -p ${DIRECTORY}/etc/pki/tls/certs
        ${DIRECTORY} -m 0644 -o root -g root /etc/pki/tls/certs/ca-bundle.crt ${DIRECTORY}/etc/pki/tls/certs/ca-bundle.crt
    else
        mkdir -p ${DIRECTORY}/etc/ssl/certs
        ln /etc/ssl/certs/ca-certificates.crt ${DIRECTORY}/etc/ssl/certs/
    fi
}
