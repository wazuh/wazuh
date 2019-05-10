#!/usr/bin/env bash

# Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

PREDEF_FILE=./preloaded_vars.conf
TRUE="true";
FALSE="false";

isFile()
{
    FILE=$1
    ls ${FILE} >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo "${TRUE}"
        return 0;
    fi
    echo "${FALSE}"
    return 1;
}

# Aux functions
print() {
    echo -e $1
}

error_and_exit() {
    echo "Error executing command: '$1'."
    echo 'Exiting.'
    exit 1
}

exec_cmd_bash() {
    bash -c "$1" || error_and_exit "$1"
}

exec_cmd() {
    eval $1 > /dev/null 2>&1 || error_and_exit "$1"
}

get_configuration_value () { # $1 setting
    cat "$API_PATH/configuration/config.js" | grep -P "config.$1\s*=\s*\"" | grep -P '".*"' -o | tr -d '"'
}

edit_configuration() { # $1 -> setting,  $2 -> value
    sed -i "s/^config.$1\s=.*/config.$1 = \"$2\";/g" "$API_PATH/configuration/config.js" || error_and_exit "sed (editing configuration)"
}

get_type_service() {
    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        echo "systemctl"
    else
        echo "service"
    fi
}

check_program_installed() {
    hash $1 > /dev/null 2>&1
    if [ "$?" != "0" ]; then
        print "command $1 not found. is it installed?."
        exit 1
    fi
}
# END Aux functions

previous_checks() {
    # Test root permissions
    if [ "$EUID" -ne 0 ]; then
        print "Please run this script with root permissions.\nExiting."
        exit 1
    fi

    # Paths
    OSSEC_CONF="/etc/ossec-init.conf"
    DEF_OSSDIR="/var/ossec"

    if ! [ -f $OSSEC_CONF ]; then
        print "Can't find $OSSEC_CONF. Is OSSEC installed?.\nExiting."
        exit 1
    fi

    . $OSSEC_CONF

    if [ -z "$DIRECTORY" ]; then
        DIRECTORY=$DEF_OSSDIR
    fi

    serv_type=$(get_type_service)
    API_PATH="${DIRECTORY}/api"

    # Dependencies
    check_program_installed "openssl"
}

change_port () {
    print ""

    if [[ "X${PORT}" != "X" ]]; then
        print "Using $PORT port."
        edit_configuration "port" $PORT
#    else
#        read -p "TCP port [55000]: " port
#        if [ "X${port}" == "X" ] || [ "X${port}" == "X55000" ]; then
#            edit_configuration "port" "55000"
#            print "Using TCP port 55000."
#        else
#            edit_configuration "port" $port
#            print "Changing TCP port to $port."
#        fi
    fi
}

change_https () {
    print ""
    https_preloaded=""

    if [[ "X${HTTPS}" != "X" ]]; then
        case $HTTPS in
            [yY] ) edit_configuration "https" "yes"
                   subject=$(echo "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG_NAME/O=$ORG_UNIT/CN=$COMMON_NAME")

                    # Step 1
                   exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key -passout pass:$PASSWORD 2048 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key -passin pass:$PASSWORD"

                   # Step 2
                   exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr -subj \"$subject\""
                   exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 2048 -in server.csr -signkey server.key -out server.crt -passin pass:$PASSWORD"
                   exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"
                   exec_cmd "chmod 400 $API_PATH/configuration/ssl/server.*"

                   print "HTTPS enabled."
                   print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"

                   cd $CURRENT_PATH;;

            [nN] ) edit_configuration "https" "no"
                   print "Using HTTP (not secure).";;
        esac

    else
        read -p "Enable HTTPS and generate SSL certificate? [Y/n/s]: " https
        if [ "X${https,,}" == "X" ] || [ "X${https,,}" == "Xy" ]; then
            edit_configuration "https" "yes"

            print ""
            read -p "Step 1: Create key [Press Enter]" enter
            exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key 2048 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key"

            print ""
            read -p "Step 2: Create self-signed certificate [Press Enter]" enter
            exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr"
            exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 2048 -in server.csr -signkey server.key -out server.crt"
            exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"

            exec_cmd "chmod 600 $API_PATH/configuration/ssl/server.*"
            print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"

            read -p "Continue with next section [Press Enter]" enter
        elif [ "X${https,,}" == "Xn" ]; then
            edit_configuration "https" "no"
            print "Using HTTP (not secure)."
        elif [ "X${https,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
    fi

    exec_cmd "cd $CURRENT_PATH"
}

change_auth () {
    print ""

    if [[ "X${AUTH}" != "X" ]]; then
        case $AUTH in
            [yY] ) edit_configuration "basic_auth" "yes"

                   exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -bc user $USER $PASS";;

            [nN] ) auth="n"
                   print "Disabling authentication (not secure)."
                   edit_configuration "basic_auth" "no";;
        esac
    else
        read -p "Enable user authentication? [Y/n/s]: " auth
        if [ "X${auth,,}" == "X" ] || [ "X${auth,,}" == "Xy" ]; then
            auth="y"
            edit_configuration "basic_auth" "yes"

            read -p "API user: " user

            while [[ -z "$user" ]]; do
                printf "\nUser verification error: Empty user."
                printf "\nPlease introduce a new user.\n\n"
                read -p "API user: " user
            done

            stty -echo
            printf "New password: "
            read user_pass
            printf "\nRe-type new password: "
            read user_pass_chk
            while [[  "$user_pass" != "$user_pass_chk" ]] || [[ -z "$user_pass" ]]; do
                printf "\nPassword verification error: Passwords don't match or password is empty."
                printf "\nIntroduce a valid password.\n"
                printf "\nNew password: "
                read user_pass
                printf "\nRe-type new password: "
                read user_pass_chk
            done
            printf "\n"
            stty echo

            user=$(echo $user | sed 's/["'"'"']/\\&/g' | sed -e 's/|/\\|/g' | sed -e 's/`/\\`/g' | sed -e 's/(/\\(/g' | sed -e 's/)/\\)/g' | sed -e 's/&/\\&/g' | sed -e 's/;/\\;/g')
            user_pass=$(echo $user_pass | sed 's/["'"'"']/\\&/g' | sed -e 's/|/\\|/g' | sed -e 's/`/\\`/g' | sed -e 's/(/\\(/g' | sed -e 's/)/\\)/g' | sed -e 's/&/\\&/g' | sed -e 's/;/\\;/g')

            exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -bc user $user $user_pass"
        elif [ "X${auth,,}" == "Xn" ]; then
            auth="n"
            print "Disabling authentication (not secure)."
            edit_configuration "basic_auth" "no"
        elif [ "X${auth,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
    fi
}

change_proxy () {
    print ""

    if [[ "X${PROXY}" != "X" ]]; then
        case $PROXY in
            [yY] )  edit_configuration "BehindProxyServer" "yes";;
            [nN] )  edit_configuration "BehindProxyServer" "no";;
        esac
        return
    else
        read -p "is the API running behind a proxy server? [y/N/s]: " proxy
        if [ "X${proxy,,}" == "Xy" ]; then
            print "API running behind proxy server."
            edit_configuration "BehindProxyServer" "yes"
        elif [ "X${proxy,,}" == "X" ] || [ "X${proxy,,}" == "Xn" ]; then
            print "API not running behind proxy server."
            edit_configuration "BehindProxyServer" "no"
        elif [ "X${proxy,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
    fi
}

main () {

    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi

    CURRENT_PATH=$(pwd)

    previous_checks

    print "### Wazuh API Configuration ###"

    change_port
#    change_https
#    change_auth
#    change_proxy
#
#    print "\nConfiguration changed."
#
#    print "\nRestarting API."
#    if [ $serv_type == "systemctl" ]; then
#        exec_cmd "systemctl restart wazuh-api"
#    else
#        exec_cmd "service wazuh-api restart"
#    fi
#
#    print "\n### [Configuration changed] ###"
#    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
#        rm $PREDEF_FILE
#    fi
#    exit 0
}

main