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

# For solaris
echo "xxxx" | grep -E "xxx" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    if [ -x /usr/xpg4/bin/grep ]; then
        PATH=/usr/xpg4/bin:$PATH
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
    echo "4- ${installing}"

    echo ""
    echo "DIR=\"${INSTALLDIR}\""

    # Changing Config.OS with the new C flags
    # Checking if debug is enabled
    if [ "X${SET_DEBUG}" = "Xdebug" ]; then
        CEXTRA="${CEXTRA} -DDEBUGAD"
    fi

    echo "CEXTRA=${CEXTRA}" >> ./src/Config.OS

    MAKEBIN=make
    ## Find make/gmake
    if [ "X$NUNAME" = "XOpenBSD" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XFreeBSD" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XNetBSD" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XDragonflyBSD" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XBitrig" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XSunOS" ]; then
          MAKEBIN=gmake
    elif [ "X$NUNAME" = "XHP-UX" ]; then
          MAKEBIN=/usr/local/bin/gmake
    elif [ "X$NUNAME" = "XAIX" ]; then
          MAKEBIN=/opt/freeware/bin/gmake
    fi
    if [ $(grep "Alpine Linux" /etc/os-release > /dev/null  && echo 1) ]; then
        ALPINE_DEPS="EXTERNAL_SRC_ONLY=1"
    fi

    # On CentOS <= 5 we need to disable syscollector compilation
    OS_VERSION_FOR_SYSC="${DIST_NAME}"
    if ([ "X${OS_VERSION_FOR_SYSC}" = "Xrhel" ] || [ "X${OS_VERSION_FOR_SYSC}" = "Xcentos" ]) && [ ${DIST_VER} -le 5 ]; then
        AUDIT_FLAG="USE_AUDIT=no"
        MSGPACK_FLAG="USE_MSGPACK_OPT=no"
        if [ ${DIST_VER} -lt 5 ]; then
            SYSC_FLAG="DISABLE_SYSC=yes"
        fi
    fi

    # Makefile
    echo " - ${runningmake}"
    echo ""

    cd ./src

    # Binary install will use the previous generated code.
    if [ "X${USER_BINARYINSTALL}" = "X" ]; then
        # Download external libraries if missing
        find external/* > /dev/null 2>&1 || ${MAKEBIN} deps ${ALPINE_DEPS} TARGET=${INSTYPE}

        if [ "X${OPTIMIZE_CPYTHON}" = "Xy" ]; then
            CPYTHON_FLAGS="OPTIMIZE_CPYTHON=yes"
        fi

        # Add DATABASE=pgsql or DATABASE=mysql to add support for database
        # alert entry
        ${MAKEBIN} TARGET=${INSTYPE} INSTALLDIR=${INSTALLDIR} ${SYSC_FLAG} ${MSGPACK_FLAG} ${AUDIT_FLAG} ${CPYTHON_FLAGS} -j${THREADS} build

        if [ $? != 0 ]; then
            cd ../
            catError "0x5-build"
        fi
    fi

    # If update, stop Wazuh
    if [ "X${update_only}" = "Xyes" ]; then
        echo "Stopping Wazuh..."
        UpdateStopOSSEC
    fi

    if [ "X${update_only}" = "Xyes" ]; then
        WazuhPreUpgrade $INSTYPE
    fi

    # Install
    InstallWazuh

    cd ../

    # Install Wazuh ruleset updater
    if [ "X$INSTYPE" = "Xserver" ]; then
        WazuhSetup
    fi

    # Calling the init script to start Wazuh during boot
    runInit $INSTYPE ${update_only}
    runinit_value=$?

    # If update, start Wazuh
    if [ "X${update_only}" = "Xyes" ]; then
        WazuhUpgrade $INSTYPE
        # Update versions previous to Wazuh 1.2
        UpdateOldVersions
        echo "Starting Wazuh..."
        UpdateStartOSSEC
    fi

    if [ $runinit_value = 1 ]; then
        notmodified="yes"
    elif [ "X$START_WAZUH" = "Xyes" ]; then
        echo "Starting Wazuh..."
        UpdateStartOSSEC
    fi

}

##########
# UseSyscheck()
##########
UseSyscheck()
{
    # Integrity check config
    echo ""
    $ECHO "  3.2- ${runsyscheck} ($yes/$no) [$yes]: "
    if [ "X${USER_ENABLE_SYSCHECK}" = "X" ]; then
        read AS
    else
        AS=${USER_ENABLE_SYSCHECK}
    fi
    echo ""
    case $AS in
        $nomatch)
            echo "   - ${nosyscheck}."
            ;;
        *)
            SYSCHECK="yes"
            echo "   - ${yessyscheck}."
            ;;
    esac
}


##########
# UseRootcheck()
##########
UseRootcheck()
{
    # Rootkit detection configuration
    echo ""
    $ECHO "  3.3- ${runrootcheck} ($yes/$no) [$yes]: "

    if [ "X${USER_ENABLE_ROOTCHECK}" = "X" ]; then
        read ES
    else
        ES=${USER_ENABLE_ROOTCHECK}
    fi

    echo ""
    case $ES in
        $nomatch)
            echo "   - ${norootcheck}."
            ;;
        *)
            ROOTCHECK="yes"
            echo "   - ${yesrootcheck}."
            ;;
    esac
}

UseSyscollector()
{
    # Syscollector config predefined (is overwritten by the preload-vars file)
    if [ "X${USER_ENABLE_SYSCOLLECTOR}" = "Xn" ]; then
        SYSCOLLECTOR="no"
     else
         SYSCOLLECTOR="yes"
     fi
}

UseSecurityConfigurationAssessment()
{
    # Configuration assessment config predefined (is overwritten by the preload-vars file)
    if [ "X${USER_ENABLE_SCA}" = "Xn" ]; then
        SECURITY_CONFIGURATION_ASSESSMENT="no"
     else
        SECURITY_CONFIGURATION_ASSESSMENT="yes"
     fi
}

UseSSLCert()
{
    if [ "X${USER_CREATE_SSL_CERT}" = "Xn" ]; then
        SSL_CERT="no"
    else
        SSL_CERT="yes"
    fi
}

UseUpdateCheck()
{
    # Update_check config predefined (is overwritten by the preload-vars file)
    if [ "X${USER_ENABLE_UPDATE_CHECK}" = "Xn" ]; then
        UPDATE_CHECK="no"
     else
        UPDATE_CHECK="yes"
     fi
}

##########
# EnableAuthd()
##########
EnableAuthd()
{
    # Authd config
    NB=$1
    echo ""
    $ECHO "  $NB - ${runauthd} ($yes/$no) [$yes]: "
    if [ "X${USER_ENABLE_AUTHD}" = "X" ]; then
        read AS
    else
        AS=${USER_ENABLE_AUTHD}
    fi
    echo ""
    case $AS in
        $nomatch)
            AUTHD="no"
            echo "   - ${norunauthd}."
            ;;
        *)
            AUTHD="yes"
            echo "   - ${yesrunauthd}."
            ;;
    esac
}

##########
# ConfigureBoot()
##########
ConfigureBoot()
{
    NB=$1
    if [ "X$INSTYPE" != "Xagent" ]; then

        echo ""
        $ECHO "  $NB- ${startwazuh} ($yes/$no) [$yes]: "

        if [ "X${USER_AUTO_START}" = "X" ]; then
            read ANSWER
        else
            ANSWER=${USER_AUTO_START}
        fi

        echo ""
        case $ANSWER in
            $nomatch)
                echo "   - ${nowazuhstart}"
                ;;
            *)
                START_WAZUH="yes"
                echo "   - ${yeswazuhstart}"
                ;;
        esac
    fi
}

##########
# SetupLogs()
##########
SetupLogs()
{
    NB=$1
    echo ""
    echo "  $NB- ${readlogs}"
    echo ""

    WriteLogs "echo"

    echo ""
    catMsg "0x106-logs"

    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi
}


##########
# ConfigureClient()
##########
ConfigureClient()
{
    echo ""
    echo "3- ${configuring} $NAME."
    echo ""

    if [ "X${USER_AGENT_SERVER_IP}" = "X" -a "X${USER_AGENT_SERVER_NAME}" = "X" ]; then
        # Looping and asking for server ip or hostname
        while [ 1 ]; do
            $ECHO "  3.1- ${serveraddr}: "
                read ADDRANSWER
            # Is it an IP?
            echo $ADDRANSWER | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
                    echo ""
                SERVER_IP=$ADDRANSWER
                    echo "   - ${addingip} $IP"
                break;
            # Must be a name
            elif [ $? != 0 ]; then
                    echo ""
                HNAME=$ADDRANSWER
                    echo "   - ${addingname} $HNAME"
                break;
            fi
        done
    else
        SERVER_IP=${USER_AGENT_SERVER_IP}
        HNAME=${USER_AGENT_SERVER_NAME}
    fi

    # Syscheck?
    UseSyscheck

    # Rootcheck?
    UseRootcheck

    UseSyscollector

    UseSecurityConfigurationAssessment

    echo ""
    $ECHO "  3.5 - ${enable_ar} ($yes/$no) [$yes]: "

    if [ "X${USER_ENABLE_ACTIVE_RESPONSE}" = "X" ]; then
        read ANY
    else
        ANY=${USER_ENABLE_ACTIVE_RESPONSE}
    fi

    case $ANY in
        $nomatch)
            echo ""
            echo "   - ${noactive}."
            ;;
        *)
            ACTIVERESPONSE="yes"
            echo ""
            echo "   - ${yesactive}."
            ;;
    esac

    # Set up CA store
    catMsg "0x109-castore"
    AddCAStore

    # Set up the log files
    SetupLogs "3.7"

    # Write configuration
    WriteAgent
}

##########
# ConfigureServer()
##########
ConfigureServer()
{
    echo ""
    echo "3- ${configuring} $NAME."


    # Configuring e-mail notification
    echo ""
    $ECHO "  3.1- ${mailnotify} ($yes/$no) [$no]: "

    if [ "X${USER_ENABLE_EMAIL}" = "X" ]; then
        read ANSWER
    else
        ANSWER=${USER_ENABLE_EMAIL}
    fi

    case $ANSWER in
        $yesmatch)
            EMAILNOTIFY="yes"
            $ECHO "   - ${whatsemail} "
            if [ "X${USER_EMAIL_ADDRESS}" = "X" ]; then

                read EMAIL
                echo "${EMAIL}" | grep -E "^[a-zA-Z0-9_.+-]{1,36}@[a-zA-Z0-9_.-]{1,54}$" > /dev/null 2>&1 ;RVAL=$?;
                # Ugly e-mail validation
                while [ "$EMAIL" = "" -o ! ${RVAL} = 0 ] ; do
                    $ECHO "   - ${whatsemail} "
                    read EMAIL
                    echo "${EMAIL}" | grep -E "^[a-zA-Z0-9_.+-]{1,36}@[a-zA-Z0-9_.-]{1,54}$" > /dev/null 2>&1 ;RVAL=$?;
                done
            else
                EMAIL=${USER_EMAIL_ADDRESS}
            fi

            if [ -x "$HOST_CMD" ]; then
              HOSTTMP=`${HOST_CMD} -W 5 -t mx wazuh.com 2>/dev/null`
              if [ $? = 1 ]; then
                 # Trying without the -W
                 HOSTTMP=`${HOST_CMD} -t mx wazuh.com 2>/dev/null`
              fi
              echo "x$HOSTTMP" | grep "wazuh.com mail is handled" > /dev/null 2>&1
              if [ $? = 0 ]; then
                 # Breaking down the user e-mail
                 EMAILHOST=`echo ${EMAIL} | cut -d "@" -f 2`
                 if [ "X${EMAILHOST}" = "Xlocalhost" ]; then
                    SMTPHOST="127.0.0.1"
                 else
                    HOSTTMP=`${HOST_CMD} -W 5 -t mx ${EMAILHOST}`
                    SMTPHOST=`echo ${HOSTTMP} | cut -d " " -f 7`
                 fi
              fi
            fi

            if [ "X${USER_EMAIL_SMTP}" = "X" ]; then
                if [ "X${SMTPHOST}" != "X" ]; then
                    echo ""
                    echo "   - ${yoursmtp}: ${SMTPHOST}"
                    $ECHO "   - ${usesmtp} ($yes/$no) [$yes]: "
                    read EMAIL2
                    case ${EMAIL2} in
                        $nomatch)
                        echo ""
                        SMTP=""
                        ;;
                    *)
                        SMTP=${SMTPHOST}
                        echo ""
                        echo "   --- ${usingsmtp} ${SMTP}"
                        ;;
                    esac
                fi

                if [ "X${SMTP}" = "X" ]; then
                    $ECHO "   - ${whatsmtp} "
                    read SMTP
                fi
            else
                SMTP=${USER_EMAIL_SMTP}
            fi
        ;;
        *)
            echo ""
            echo "   --- ${nomail}."
            EMAILNOTIFY="no"
        ;;
    esac

    # Checking if syscheck should run
    UseSyscheck

    # Checking if rootcheck should run
    UseRootcheck

    UseSyscollector

    UseSecurityConfigurationAssessment

    # Active response
    catMsg "0x107-ar"

    echo ""
    echo "   - ${defaultwhitelist}"

    for ip in ${NAMESERVERS} ${NAMESERVERS2};
    do
    if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
        echo "      - ${ip}"
    fi
    done

    AddWhite

    if [ "X$INSTYPE" = "Xserver" ]; then
      # Configuring remote syslog
      echo ""
      $ECHO "  3.6- ${syslog} ($yes/$no) [$yes]: "

      if [ "X${USER_ENABLE_SYSLOG}" = "X" ]; then
        read ANSWER
      else
        ANSWER=${USER_ENABLE_SYSLOG}
      fi

      echo ""
      case $ANSWER in
        $nomatch)
            echo "   --- ${nosyslog}."
            ;;
        *)
            echo "   - ${yessyslog}."
            RLOG="yes"
            ;;
      esac

      # Configuring remote connections
      SLOG="yes"
    fi

    UseSSLCert

    # Setting up the auth daemon & logs
    if [ "X$INSTYPE" = "Xserver" ]; then
        EnableAuthd "3.7"
        ConfigureBoot "3.8"
        SetupLogs "3.9"
        UseUpdateCheck
        WriteManager
    else
        ConfigureBoot "3.6"
        SetupLogs "3.7"
        WriteLocal
    fi
}

##########
# setInstallDir()
##########
setInstallDir()
{
    if [ "X${USER_DIR}" = "X" ]; then
        # If we don't have a value in USER_DIR, it means that the user
        # should specify the installation directory.
        while [ 1 ]; do
            echo ""
            $ECHO "2- ${wheretoinstall} [$INSTALLDIR]: "
            read ANSWER
            if [ ! "X$ANSWER" = "X" ]; then
                echo $ANSWER |grep -E "^/[a-zA-Z0-9./_-]{3,128}$">/dev/null 2>&1
                if [ $? = 0 ]; then
                    INSTALLDIR=$ANSWER;
                    break;
                fi
            else
                break;
            fi
        done
    else
        # This else statement handles the case in which it was determined that the installation
        # is an upgrade. So, the USER_DIR variable was previously set with the value of PREINSTALLEDDIR.
        # Another possibility is that USER_DIR could have been set before running the script in
        # order to run an unattended installation.
        INSTALLDIR=${USER_DIR}
    fi
}

##########
# setEnv()
##########
setEnv()
{
    echo ""
    echo "    - ${installat} ${INSTALLDIR} ."

    if [ "X$INSTYPE" = "Xagent" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        CEXTRA="$CEXTRA -DLOCAL"
    fi
}

##########
# askForDelete()
##########
askForDelete()
{
    if [ -d "$INSTALLDIR" ]; then
        if [ "X${USER_DELETE_DIR}" = "X" ]; then
            echo ""
            $ECHO "    - ${deletedir} ($yes/$no) [$no]: "
            read ANSWER
        else
            ANSWER=${USER_DELETE_DIR}
        fi

        case $ANSWER in
            $yesmatch)
                echo "      Stopping Wazuh..."
                UpdateStopOSSEC
                rm -rf $INSTALLDIR
                if [ ! $? = 0 ]; then
                    echo "Error deleting ${INSTALLDIR}"
                    exit 2;
                fi
                ;;
        esac
    fi
}

##########
# checkDependencies()
# Thanks to gabriel@macacos.org
##########
checkDependencies()
{
    echo ""
    OLDOPATH=$PATH
    if [ "X$NUNAME" = "XSunOS" ]; then
        PATH=$PATH:/usr/ccs/bin:/usr/xpg4/bin:/opt/csw/gcc3/bin:/opt/csw/bin:/usr/sfw/bin
        export  PATH
    elif [ "X$NUNAME" = "XAIX" ]; then
        PATH=$PATH:/usr/vac/bin
        export  PATH
    fi

    PATH=$OLDOPATH
    export PATH
}

##########
# AddWhite()
##########
AddWhite()
{
    while [ 1 ]
    do
        echo ""
        $ECHO "   - ${addwhite} ($yes/$no)? [$no]: "

        # If white list is set, we don't need to ask it here.
        if [ "X${USER_WHITE_LIST}" = "X" ]; then
            read ANSWER
        else
            ANSWER=${USER_WHITE_LIST}
        fi

        if [ "X${ANSWER}" = "X" ] ; then
            ANSWER=$no
        fi

        case $ANSWER in
            $no)
                break;
                ;;
            *)
                SET_WHITE_LIST="true"
                $ECHO "   - ${ipswhite}"
                if [ "X${USER_WHITE_LIST}" = "X" ]; then
                    read IPS
                else
                    IPS=${USER_WHITE_LIST}
                fi

                break;
                ;;
        esac
    done
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
# AddPFTable()
##########
AddPFTable()
{
    #default pf rules
    TABLE="wazuh_fwtable"

    # Add table to the first line
    echo ""
    echo "   - ${pfmessage}:"
    echo "     ${moreinfo}"
    echo "     https://documentation.wazuh.com"

    echo ""
    echo ""
    echo "      table <${TABLE}> persist #$TABLE "
    echo "      block in quick from <${TABLE}> to any"
    echo "      block out quick from any to <${TABLE}>"
    echo ""
    echo ""

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

    # Checking dependencies
    checkDependencies

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

    . ./src/init/update.sh
    # Is this an update?
    if getPreinstalledDir && [ "X${USER_CLEANINSTALL}" = "X" ]; then
        echo ""
        ct="1"
        while [ $ct = "1" ]; do
            ct="0"
            $ECHO " - ${wanttoupdate} ($yes/$no): "
            if [ "X${USER_UPDATE}" = "X" ]; then
                read ANY
            else
                ANY=$yes
            fi

            case $ANY in
                $yes)
                    update_only="yes"
                    break;
                    ;;
                $no)
                    echo ""
                    echo "${mustuninstall}"
                    exit 0;
                    ;;
                  *)
                    ct="1"
                    ;;
            esac
        done


        # Do some of the update steps.
        if [ "X${update_only}" = "Xyes" ]; then
            . ./src/init/update.sh

            if [ "`doUpdatecleanup`" = "${FALSE}" ]; then
                # Disabling update
                echo ""
                echo "${unabletoupdate}"
                sleep 5;
                update_only=""
            else
                # Get update
                USER_DIR="$PREINSTALLEDDIR"
                USER_INSTALL_TYPE=`getPreinstalledType`
                USER_OLD_VERSION=`getPreinstalledVersion`
                USER_OLD_NAME=`getPreinstalledName`
                USER_DELETE_DIR="$nomatch"
            fi

            ct="1"

            # We dont need to update the rules on agent installs
            if [ "X${USER_INSTALL_TYPE}" = "Xagent" ]; then
                ct="0"
            fi

        fi
    fi

    # Setting up the installation type
    hybrid="hybrid"
    HYBID=""
    hybridm=`echo ${hybrid} | cut -b 1`
    serverm=`echo ${server} | cut -b 1`
    localm=`echo ${local} | cut -b 1`
    agentm=`echo ${agent} | cut -b 1`
    helpm=`echo ${help} | cut -b 1`

    # If user install type is not set, ask for it.
    if [ "X${USER_INSTALL_TYPE}" = "X" ]; then

        # Loop for the installation options
        while [ 1 ]
        do
            echo ""
            $ECHO "1- ${whattoinstall} "

            read ANSWER
            case $ANSWER in

                ${helpm}|${help})
                    catMsg "0x102-installhelp"
                ;;

                ${server}|${serverm}|"manager"|"m")
                    echo ""
                    echo "  - ${serverchose}."
                    INSTYPE="server"
                    break;
                ;;

                ${agent}|${agentm}|"a")
                    echo ""
                    echo "  - ${clientchose}."
                    INSTYPE="agent"
                    break;
                ;;

                ${hybrid}|${hybridm})
                    echo ""
                    echo "  - ${serverchose} (hybrid)."
                    INSTYPE="server"
                    HYBID="go"
                    break;
                ;;
                ${local}|${localm})
                    echo ""
                    echo "  - ${localchose}."
                    INSTYPE="local"
                    break;
                ;;
            esac
        done

    else
        INSTYPE=${USER_INSTALL_TYPE}
    fi

    # Setting up the installation directory
    setInstallDir

    # Setting up the environment
    setEnv

    # Ask to remove the current installation if exists
    askForDelete

    # Configuring the system (based on the installation type)
    if [ "X${update_only}" = "X" ]; then
        if [ "X$INSTYPE" = "Xserver" ]; then
            ConfigureServer
        elif [ "X$INSTYPE" = "Xagent" ]; then
            ConfigureClient
        elif [ "X$INSTYPE" = "Xlocal" ]; then
            ConfigureServer
        else
            catError "0x4-installtype"
        fi
    fi

    # Installing (calls the respective script
    # -- InstallAgent.sh or InstallServer.sh
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
    echo " - ${configat} $INSTALLDIR/etc/ossec.conf"
    echo ""


    catMsg "0x103-thanksforusing"


    if [ "X${update_only}" = "Xyes" ]; then
        # Message for the update
        if [ "X`sh ./src/init/fw-check.sh`" = "XPF" ]; then
            if [ "X$USER_NO_STOP" = "X" ]; then
                read ANY
            fi
            AddPFTable
        fi
        echo ""

        # If version < wazuh 1.2
        if [ "X$USER_OLD_NAME" != "XWazuh" ]; then
            echo " ====================================================================================="
            echo "  ${update_rev_newconf1}"
            echo "  ${update_rev_newconf2}"
            echo " ====================================================================================="
            echo " "
        fi
        echo " - ${updatecompleted}"
        echo ""
        exit 0;
    fi


    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi


    # PF firewall message
    if [ "X`sh ./src/init/fw-check.sh`" = "XPF" ]; then
        AddPFTable
    fi


    if [ "X$INSTYPE" = "Xserver" ]; then
        echo ""
        echo " - ${addserveragent}"
        echo ""
        echo "   ${moreinfo}"
        echo "   https://documentation.wazuh.com/"
        echo ""

    elif [ "X$INSTYPE" = "Xagent" ]; then
        echo ""
        echo " - ${moreinfo}"
        echo "   https://documentation.wazuh.com/"
        echo ""
    fi

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


if [ "x$HYBID" = "xgo" ]; then
    echo "   --------------------------------------------"
    echo "   Finishing Hybrid setup (agent configuration)"
    echo "   --------------------------------------------"
    echo 'USER_LANGUAGE="en"' > ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_INSTALL_TYPE="agent"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo "USER_DIR=\"$INSTALLDIR/ossec-agent\"" >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_ENABLE_ROOTCHECK="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_ENABLE_SYSCHECK="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_ENABLE_SYSCOLLECTOR="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_ENABLE_SCA="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_CREATE_SSL_CERT="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_ENABLE_ACTIVE_RESPONSE="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_UPDATE="n"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf
    echo 'USER_CLEANINSTALL="y"' >> ./etc/preloaded-vars.conf
    echo "" >> ./etc/preloaded-vars.conf

   cd src && ${MAKEBIN} clean && cd ..
   ./install.sh
   rm etc/preloaded-vars.conf
fi

exit 0

#### exit ? ###
