#!/bin/sh
# Copyright (C) 2015, Wazuh Inc.
# Installation script for Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

### Looking up for the execution directory
cd `dirname $0`


### Looking for echo -n
ECHO="echo -n"
hs=`echo -n "a"`
if [ ! "X$hs" = "Xa" ]; then
    if [ -x /usr/ucb/echo ]; then
        ECHO="/usr/ucb/echo -n"
    elif [ -x /bin/echo ]; then
        ECHO="/bin/echo -n"
    else
        ECHO=echo
    fi
fi

# Initializing vars
SET_DEBUG=""

# Checking for command line arguments
for i in $*; do
    if [ "X$i" = "Xdebug" ]; then
        SET_DEBUG="debug"
    elif [ "X$i" = "Xbinary-install" ]; then
        USER_BINARYINSTALL="yes"
    elif [ "X$i" = "Xhelp" ]; then
        echo "$0 debug"
        echo "$0 binary-install"
        exit 1;
    fi
done

##########
# install()
##########
Install()
{
    echo ""
    echo "${installing}"

    echo ""
    echo "DIR=\"${INSTALLDIR}\""

    MAKEBIN=make

    # Makefile
    echo " - ${runningmake}"
    echo ""

    cd ./src

    # Build compiled code.
    BuildEngine
    BuildKeystore

    # Install
    InstallWazuh

    cd ../

    # Calling the init script to start Wazuh during boot
    runInit
    runinit_value=$?
}

##########
# AddCAStore()
##########
AddCAStore()
{
    while [ 1 ]
    do
        echo ""
        $ECHO "   - ${addcastore} ($yes/$no)? [$no]: "

        # If white list is set, we don't need to ask it here.
        if [ "X${USER_CA_STORE}" = "X" ]; then
            read ANSWER
        else
            ANSWER=${USER_CA_STORE}
        fi

        if [ "X${ANSWER}" = "X" ] ; then
            ANSWER=$no
        fi

        case $ANSWER in
            $no)
                break;
                ;;
            *)
                SET_CA_STORE="true"
                $ECHO "   - ${castore}"
                if [ "X${USER_CA_STORE}" = "X" ]; then
                    read CA_STORE
                else
                    CA_STORE=${USER_CA_STORE}
                fi

                break;
                ;;
        esac
    done

    # Check the certificate

    if [ -n "$CA_STORE" ]
    then
        if [ -f $CA_STORE ]
        then
            if hash openssl 2>&1 > /dev/null && [ $(date -d "$(openssl x509 -enddate -noout -in $CA_STORE | cut -d = -f 2)" +%s) -lt $(date +%s) ]
            then
                echo ""
                echo "     Warning: the certificate at \"$CA_STORE\" is expired."
            fi
        elif [ ! -d $CA_STORE ]
        then
            echo ""
            echo "     Warning: No such file or directory \"$CA_STORE\"."
        fi
    fi
}

##########
# main()
##########
main()
{
    LG="en"
    LANGUAGE="en"
    . ./src/init/dist-detect.sh
    . ./src/init/shared.sh
    . ./src/init/functions.sh

    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi

    # If user language is not set

    if [ "X${USER_LANGUAGE}" = "X" ]; then

        # Choosing the language.
        while [ 1 ]; do
        echo ""
        for i in `ls ${TEMPLATE}`; do
            # ignore CVS (should not be there anyways and config)
            if [ "$i" = "CVS" -o "$i" = "config" ]; then continue; fi
            cat "${TEMPLATE}/$i/language.txt"
            if [ ! "$i" = "en" ]; then
                LG="${LG}/$i"
            fi
        done
        $ECHO "  (${LG}) [en]: "
        read USER_LG;

        if [ "X${USER_LG}" = "X" ]; then
            USER_LG="en"
        fi

        if [ -d "${TEMPLATE}/${USER_LG}" ]; then
            break;
        fi
        done;

        LANGUAGE=${USER_LG}

    else

        # If provided language is not valid, default to english
        if [ -d "${TEMPLATE}/${USER_LANGUAGE}" ]; then
            LANGUAGE=${USER_LANGUAGE}
        else
            LANGUAGE="en"
        fi

    fi # for USER_LANGUAGE

    . ./src/init/language.sh
    . ./src/init/init.sh
    . ./src/init/wazuh/wazuh.sh
    . ${TEMPLATE}/${LANGUAGE}/messages.txt
    . ./src/init/inst-functions.sh
    . ./src/init/template-select.sh

    # Must be executed as ./install.sh
    if [ `isFile ${VERSION_FILE}` = "${FALSE}" ]; then
        catError "0x1-location";
    fi

    # Must be root
    if [ ! "X$ME" = "Xroot" ]; then
        catError "0x2-beroot";
    fi

    if [ "X$USER_NO_STOP" = "X" ]; then
        clear 2> /dev/null
    fi

    # Initial message
    echo " $NAME $VERSION (Rev. $REVISION) ${installscript} - https://www.wazuh.com"
    catMsg "0x101-initial"
    echo ""
    echo "  - $system: $UNAME (${DIST_NAME} ${DIST_VER}.${DIST_SUBVER})"
    echo "  - $user: $ME"
    echo "  - $host: $HOST"
    echo ""
    echo ""
    echo "  -- $hitanyorabort --"

    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi

    Install

    # User messages
    echo ""
    echo " - ${configurationdone}."
    echo ""
    echo " - ${tostart}:"
    echo "      $INSTALLDIR/bin/wazuh-control start"
    echo ""
    echo " - ${tostop}:"
    echo "      $INSTALLDIR/bin/wazuh-control stop"
    echo ""
    echo ""


    catMsg "0x103-thanksforusing"


    echo ""
    echo " - ${addserveragent}"
    echo ""
    echo "   ${moreinfo}"
    echo "   https://documentation.wazuh.com/"
    echo ""


    if [ "X$notmodified" = "Xyes" ]; then
        catMsg "0x105-noboot"
        echo "      $INSTALLDIR/bin/wazuh-control start"
        echo ""
    fi
}

_f_cfg="./install.cfg.sh"

if [ -f $_f_cfg ]; then
  . $_f_cfg
fi

### Calling main function where everything happens
main

exit 0

#### exit ? ###
