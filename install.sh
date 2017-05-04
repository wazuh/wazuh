#!/bin/sh
# Installation script for the OSSEC
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Nov 25, 2016

# Changelog 19/03/2006 - Rafael M. Capovilla <under@underlinux.com.br>
# New function AddWhite to allow users to add more Ips in the white_list
# Minor *echos* modifications to better look
# Bug fix - When email address is blank
# Bug fix - delete INSTALLDIR - Default is yes but if the user just press enter the script wasn't deleting it as it should
# Changelog 15/07/2006 - Rafael M. Capovilla <under@underlinux.com.br>
# New function AddTable to add support for OpenBSD pf rules in firewall-drop active response

# Changelog 29 March 2012 - Adding hybrid mode (standalone + agent)
# Changelog 25 November 2016 - Added OpenSCAP, new file generating functions using templates.


### Looking up for the execution directory
cd `dirname $0`


### Looking for echo -n
ECHO="echo -n"
hs=`echo -n "a"`
if [ ! "X$hs" = "Xa" ]; then
    if [ -x /usr/ucb/echo ]; then
        ECHO="/usr/ucb/echo -n"
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

    echo "DIR=\"${INSTALLDIR}\"" > ${LOCATION}

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
    fi


    # Makefile
    echo " - ${runningmake}"
    cd ./src

    # Binary install will use the previous generated code.
    if [ "X${USER_BINARYINSTALL}" = "X" ]; then
        # Add DATABASE=pgsql or DATABASE=mysql to add support for database
        # alert entry
        ${MAKEBIN} PREFIX=${INSTALLDIR} TARGET=${INSTYPE} build
        if [ $? != 0 ]; then
            cd ../
            catError "0x5-build"
        fi
    fi

    # If update, stop ossec
    if [ "X${update_only}" = "Xyes" ]; then
        UpdateStopOSSEC
    fi

    ${MAKEBIN} PREFIX=${INSTALLDIR} TARGET=${INSTYPE} install

    cd ../

    # Generate the /etc/ossec-init.conf
    VERSION=`cat ${VERSION_FILE}`
    REVISION=`cat ${REVISION_FILE}`
    chmod 700 ${OSSEC_INIT} > /dev/null 2>&1
    GenerateInitConf > ${OSSEC_INIT}
    chmod 640 ${OSSEC_INIT}
    chown root:ossec ${OSSEC_INIT}
    ln -sf ${OSSEC_INIT} ${INSTALLDIR}${OSSEC_INIT}

    # Install Wazuh ruleset updater
    if [ "X$INSTYPE" = "Xserver" ]; then
        WazuhSetup
    fi

    # If update, start OSSEC
    if [ "X${update_only}" = "Xyes" ]; then
        WazuhUpgrade
        # Update versions previous to Wazuh 1.2
        UpdateOldVersions
        UpdateStartOSSEC
    fi

    # Calling the init script  to start ossec hids during boot
    if [ "X${update_only}" = "X" ]; then
        runInit $INSTYPE
        if [ $? = 1 ]; then
            notmodified="yes"
        fi
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

##########
# UseOpenSCAP()
##########
UseOpenSCAP()
{
    # OpenSCAP config
    echo ""
    $ECHO "  3.4- ${runopenscap} ($yes/$no) [$yes]: "
    if [ "X${USER_ENABLE_OPENSCAP}" = "X" ]; then
        read AS
    else
        AS=${USER_ENABLE_OPENSCAP}
    fi
    echo ""
    case $AS in
        $nomatch)
            echo "   - ${norunopenscap}."
            ;;
        *)
            OPENSCAP="yes"
            echo "   - ${yesrunopenscap}."
            ;;
    esac
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

    # OpenSCAP?
    UseOpenSCAP

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
            ;;
    esac

    # Set up the log files
    SetupLogs "3.6"

    # echo "</ossec_config>" >> $NEWCONFIG
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

    # Checking if OpenSCAP should run
    UseOpenSCAP

    # Active response
    catMsg "0x107-ar"

    echo ""
    echo "   - ${defaultwhitelist}"

    for ip in ${NAMESERVERS} ${NAMESERVERS2};
    do
    if [ ! "X${ip}" = "X" ]; then
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

    # Setting up the logs
    SetupLogs "3.7"

    WriteManager

}

##########
# setEnv()
##########
setEnv()
{
    echo ""
    echo "2- ${settingupenv}."

    echo ""
    if [ "X${USER_DIR}" = "X" ]; then
        while [ 1 ]; do
            $ECHO " - ${wheretoinstall} [$INSTALLDIR]: "
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
        INSTALLDIR=${USER_DIR}
    fi


    CEXTRA="$CEXTRA -DDEFAULTDIR=\\\"${INSTALLDIR}\\\""

    echo ""
    echo "    - ${installat} ${INSTALLDIR} ."


    if [ "X$INSTYPE" = "Xagent" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        CEXTRA="$CEXTRA -DLOCAL"
    fi

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
                rm -rf $INSTALLDIR
                if [ ! $? = 0 ]; then
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
            ANSWER=$yes
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
# AddPFTable()
##########
AddPFTable()
{
    #default pf rules
    TABLE="ossec_fwtable"

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
    echo " $NAME $VERSION ${installscript} - http://www.wazuh.com"
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
    if [ "`isUpdate`" = "${TRUE}" -a "x${USER_CLEANINSTALL}" = "x" ]; then
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
                    break;
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
                USER_INSTALL_TYPE=`getPreinstalled`
                USER_DIR=`getPreinstalledDir`
                USER_DELETE_DIR="$nomatch"
                USER_OLD_VERSION=`getPreinstalledVersion`
                USER_OLD_NAME=`getPreinstalledName`
            fi

            ct="1"

            # We dont need to update the rules on agent installs
            if [ "X${USER_INSTALL_TYPE}" = "Xagent" ]; then
                ct="0"
            fi

        fi
        echo ""
    fi

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

                ${server}|${serverm})
                    echo ""
                    echo "  - ${serverchose}."
                    INSTYPE="server"
                    break;
                ;;

                ${agent}|${agentm})
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


    # Setting up the environment
    setEnv


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
    echo "      $INSTALLDIR/bin/ossec-control start"
    echo ""
    echo " - ${tostop}:"
    echo "      $INSTALLDIR/bin/ossec-control stop"
    echo ""
    echo " - ${configat} $INSTALLDIR/etc/ossec.conf"
    echo ""


    catMsg "0x103-thanksforusing"


    if [ "X${update_only}" = "Xyes" ]; then
        # Message for the update
        if [ "X`sh ./src/init/fw-check.sh`" = "XPF" -a "X${ACTIVERESPONSE}" = "Xyes" ]; then
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
    if [ "X`sh ./src/init/fw-check.sh`" = "XPF" -a "X${ACTIVERESPONSE}" = "Xyes" ]; then
        AddPFTable
    fi


    if [ "X$INSTYPE" = "Xserver" ]; then
        echo ""
        echo " - ${addserveragent}"
        echo "   ${runma}:"
        echo ""
        echo "   $INSTALLDIR/bin/manage_agents"
        echo ""
        echo "   ${moreinfo}"
        echo "   https://documentation.wazuh.com/"
        echo ""

    elif [ "X$INSTYPE" = "Xagent" ]; then
        catMsg "0x104-client"
        echo "   $INSTALLDIR/bin/manage_agents"
        echo ""
        echo "   ${moreinfo}"
        echo "   https://documentation.wazuh.com/"
        echo ""
    fi

    if [ "X$notmodified" = "Xyes" ]; then
        catMsg "0x105-noboot"
        echo "      $INSTALLDIR/bin/ossec-control start"
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
    echo 'USER_ENABLE_OPENSCAP="n"' >> ./etc/preloaded-vars.conf
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
