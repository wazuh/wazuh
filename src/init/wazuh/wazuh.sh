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
    cp ${var_get_dir}libnss_files.so.2 $DIRECTORY/${var_get_libnss_file}libnss_files.so.2
    cp ${var_get_dir}libnss_dns.so.2 $DIRECTORY/${var_get_libnss_file}libnss_dns.so.2

    #Check if resolv.conf is a regular file or symb link
    if [ -L "/etc/resolv.conf" ]; then
        cp /etc/resolv.conf ${PREFIX}/etc/resolv.conf > /dev/null 2>&1
    else
        ln /etc/resolv.conf ${PREFIX}/etc/resolv.conf > /dev/null 2>&1
    fi
}
