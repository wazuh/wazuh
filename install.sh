#!/bin/sh
# Copyright (C) 2015, Wazuh Inc.
# Installation script for Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Resolve script location and always run from its directory.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR" || exit 1


# Select a portable "echo -n" variant for shells that do not support it.
ECHO="echo -n"
hs=$(echo -n "a")
if [ ! "X$hs" = "Xa" ]; then
    if [ -x /usr/ucb/echo ]; then
        ECHO="/usr/ucb/echo -n"
    elif [ -x /bin/echo ]; then
        ECHO="/bin/echo -n"
    else
        ECHO=echo
    fi
fi

# Initialize runtime flags.
SET_DEBUG=""

# Parse supported command-line arguments.
for i in "$@"; do
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

setBuildCextra()
{
    config_os="./src/Config.OS"
    tmp_config_os="${config_os}.tmp.$$"

    if [ -f "$config_os" ]; then
        grep -v '^CEXTRA=' "$config_os" > "$tmp_config_os"
    else
        : > "$tmp_config_os"
    fi

    echo "CEXTRA=${CEXTRA}" >> "$tmp_config_os"
    mv "$tmp_config_os" "$config_os"
}

isPFFirewall()
{
    UNAME=$(uname)
    if [ "X${UNAME}" = "XFreeBSD" ] || [ "X${UNAME}" = "XOpenBSD" ]; then
        grep -qi 'pf_enable="YES"' /etc/rc.conf 2>/dev/null
    elif [ "X${UNAME}" = "XDarwin" ]; then
        which pfctl > /dev/null 2>&1
    else
        return 1
    fi
}

##########
# install()
##########
Install()
{
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ]; then
        echo ""
        echo "4- ${installing}"

        echo ""
        echo "DIR=\"${INSTALLDIR}\""
    fi

    # Keep Config.OS idempotent: replace previous CEXTRA instead of appending on every run.
    setBuildCextra

    MAKEBIN=make
    # Select make command for BSD variants.
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
    fi
    if grep -q "Alpine Linux" /etc/os-release 2>/dev/null; then
        ALPINE_DEPS="EXTERNAL_SRC_ONLY=1"
    fi

    # Legacy RHEL/CentOS versions cannot build all modules.
    OS_VERSION_FOR_SYSC="${DIST_NAME}"
    if ([ "X${OS_VERSION_FOR_SYSC}" = "Xrhel" ] || [ "X${OS_VERSION_FOR_SYSC}" = "Xcentos" ]) && [ ${DIST_VER} -le 5 ]; then
        AUDIT_FLAG="USE_AUDIT=no"
        MSGPACK_FLAG="USE_MSGPACK_OPT=no"
        if [ ${DIST_VER} -lt 5 ]; then
            SYSC_FLAG="DISABLE_SYSC=yes"
        fi
    fi

    # Build step.
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ]; then
        echo " - ${runningmake}"
        echo ""
    fi

    cd ./src

    # "binary-install" reuses prebuilt artifacts from the workspace and skips compilation.
    if [ "X${USER_BINARYINSTALL}" = "X" ]; then
        # Download external libraries only when the folder is still empty.
        [ -z "$(find external -mindepth 1 -maxdepth 1 -type d 2>/dev/null)" ] && ${MAKEBIN} deps ${ALPINE_DEPS} TARGET=${INSTYPE}

        if [ "X${OPTIMIZE_CPYTHON}" = "Xy" ]; then
            CPYTHON_FLAGS="OPTIMIZE_CPYTHON=yes"
        fi

        # DATABASE=pgsql|mysql enables alert output through those backends.
        ${MAKEBIN} TARGET=${INSTYPE} INSTALLDIR=${INSTALLDIR} ${SYSC_FLAG} ${MSGPACK_FLAG} ${AUDIT_FLAG} ${CPYTHON_FLAGS} -j${THREADS} build

        if [ $? != 0 ]; then
            cd ../
            catError "0x5-build"
        fi
    fi

    # For updates, stop running services before replacing files.
    if [ "X${update_only}" = "Xyes" ]; then
        echo "Stopping Wazuh..."
        UpdateStopWAZUH
    fi

    # Install selected components.
    InstallWazuh

    cd ../

    # Generate/init service units and enable boot-time startup.
    runInit $INSTYPE ${update_only}
    runinit_value=$?

    # For updates, run upgrade hooks and start services again.
    if [ "X${update_only}" = "Xyes" ]; then
        WazuhUpgrade $INSTYPE
        # Compatibility migration for very old versions.
        UpdateOldVersions
        echo "Starting Wazuh..."
        UpdateStartWAZUH
    fi

    if [ $runinit_value = 1 ]; then
        notmodified="yes"
    elif [ "X$START_WAZUH" = "Xyes" ]; then
        echo "Starting Wazuh..."
        UpdateStartWAZUH
    fi

}

UseSyscollector()
{
    # Default Syscollector value (can be overridden by preloaded vars).
    setToggleVar "SYSCOLLECTOR" "${USER_ENABLE_SYSCOLLECTOR}" "yes"
}

UseSecurityConfigurationAssessment()
{
    # Default SCA value (can be overridden by preloaded vars).
    setToggleVar "SECURITY_CONFIGURATION_ASSESSMENT" "${USER_ENABLE_SCA}" "yes"
}

UseSSLCert()
{
    setToggleVar "SSL_CERT" "${USER_CREATE_SSL_CERT}" "yes"
}

UseUpdateCheck()
{
    # Default update-check value (can be overridden by preloaded vars).
    setToggleVar "UPDATE_CHECK" "${USER_ENABLE_UPDATE_CHECK}" "yes"
}

##########
# EnableAuthd()
##########
EnableAuthd()
{
    # Authd toggle.
    NB=$1
    AS=""
    PROMPTED="no"
    if [ "X${USER_ENABLE_AUTHD}" = "X" ]; then
        echo ""
        $ECHO "  $NB - ${runauthd} ($yes/$no) [$yes]: "
        read AS
        PROMPTED="yes"
    fi
    AS=${AS:-${USER_ENABLE_AUTHD}}
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
        echo ""
    fi
    case $AS in
        $nomatch)
            AUTHD="no"
            if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
                echo "   - ${norunauthd}."
            fi
            ;;
        *)
            AUTHD="yes"
            if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
                echo "   - ${yesrunauthd}."
            fi
            ;;
    esac
}

##########
# ConfigureBoot()
##########
ConfigureBoot()
{
    NB=$1
    ANSWER=""
    PROMPTED="no"
    if [ "X$INSTYPE" != "Xagent" ]; then

        if [ "X${USER_AUTO_START}" = "X" ]; then
            echo ""
            $ECHO "  $NB- ${startwazuh} ($yes/$no) [$yes]: "
            read ANSWER
            PROMPTED="yes"
        fi
        ANSWER=${ANSWER:-${USER_AUTO_START}}

        if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
            echo ""
        fi
        case $ANSWER in
            $nomatch)
                if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
                    echo "   - ${nowazuhstart}"
                fi
                ;;
            *)
                START_WAZUH="yes"
                if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ] || [ "X${PROMPTED}" = "Xyes" ]; then
                    echo "   - ${yeswazuhstart}"
                fi
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
    if [ "X${INSTALLER_BRIEF_FLOW}" = "Xyes" ]; then
        WriteLogs "echo"
        return 0
    fi

    echo ""
    echo "  $NB- ${readlogs}"
    echo ""

    WriteLogs "echo"

    echo ""
    catMsg "0x106-logs"
}


##########
# ConfigureClient()
##########
ConfigureClient()
{
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ]; then
        echo ""
        echo "3- ${configuring} $NAME."
        echo ""
    fi

    if [ "X${USER_AGENT_MANAGER_IP}" = "X" -a "X${USER_AGENT_MANAGER_NAME}" = "X" ]; then
        # Ask until a manager address/hostname is provided.
        while :; do
            if [ "X${INSTALLER_BRIEF_FLOW}" = "Xyes" ]; then
                $ECHO "  ${serveraddr}: "
            else
                $ECHO "  3.1- ${serveraddr}: "
            fi
            read ADDRANSWER
            # Check whether the input is an IPv4 address.
            if printf '%s' "$ADDRANSWER" | grep -Eq "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"; then
                echo ""
                SERVER_IP=$ADDRANSWER
                echo "   - ${addingip} ${SERVER_IP}"
                break;
            # Otherwise treat it as hostname/FQDN.
            else
                echo ""
                HNAME=$ADDRANSWER
                echo "   - ${addingname} $HNAME"
                break;
            fi
        done
    else
        SERVER_IP=${USER_AGENT_MANAGER_IP}
        HNAME=${USER_AGENT_MANAGER_NAME}
    fi

    # Keep the rest of the agent flow non-interactive after manager address input.
    setToggleVar "SYSCHECK" "${USER_ENABLE_SYSCHECK}" "yes"
    setToggleVar "ROOTCHECK" "${USER_ENABLE_ROOTCHECK}" "yes"

    UseSyscollector
    UseSecurityConfigurationAssessment

    setToggleVar "ACTIVERESPONSE" "${USER_ENABLE_ACTIVE_RESPONSE}" "yes"

    # CA store: keep legacy behavior for empty/no and allow path overrides.
    if [ -z "${USER_CA_STORE}" ]; then
        SET_CA_STORE="false"
        CA_STORE=""
    else
        ANY=$(normalizeYesNo "${USER_CA_STORE}")
        case $ANY in
            no)
                SET_CA_STORE="false"
                CA_STORE=""
                ;;
            *)
                SET_CA_STORE="true"
                CA_STORE=${USER_CA_STORE}
                if [ -f "$CA_STORE" ]; then
                    if hash openssl 2>/dev/null && \
                       [ "$(date -d "$(openssl x509 -enddate -noout -in "$CA_STORE" | cut -d= -f2)" +%s 2>/dev/null)" -lt "$(date +%s)" ] 2>/dev/null; then
                        echo ""
                        echo "     Warning: the certificate at \"$CA_STORE\" is expired."
                    fi
                elif [ ! -d "$CA_STORE" ]; then
                    echo ""
                    echo "     Warning: No such file or directory \"$CA_STORE\"."
                fi
                ;;
        esac
    fi

    # Configure logging and write agent config.
    SetupLogs "3.7"
    WriteAgent
}

##########
# ConfigureServer()
##########
ConfigureServer()
{
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ]; then
        echo ""
        echo "3- ${configuring} $NAME."

        # Active response section.
        catMsg "0x107-ar"

        echo ""
        echo "   - ${defaultwhitelist}"

        for ip in ${NAMESERVERS} ${NAMESERVERS2};
        do
        if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
            echo "      - ${ip}"
        fi
        done
    fi

    UseSSLCert

    # Configure auth daemon, boot behavior, logs, and write config.
    if [ "X$INSTYPE" = "Xmanager" ]; then
        EnableAuthd "3.7"
        ConfigureBoot "3.8"
        SetupLogs "3.9"
        UseUpdateCheck
        WriteManager
    fi
}

##########
# setInstallDir()
##########
setInstallDir()
{
    # USER_DIR overrides the default path derived from install type.
    if [ "X${USER_DIR}" != "X" ]; then
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
    fi
}

##########
# askForDelete()
##########
askForDelete()
{
    # Updates must never remove the installation directory.
    if [ "X${update_only}" = "Xyes" ]; then
        return 0
    fi

    if [ -d "$INSTALLDIR" ]; then
        # Reject overlay installs when clean-install mode is requested.
        if [ "X${USER_CLEANINSTALL}" != "X" ]; then
            CLEANINSTALL_ANY=$(normalizeYesNo "${USER_CLEANINSTALL}")
            case $CLEANINSTALL_ANY in
                yes)
                    ANY=$(normalizeYesNo "${USER_DELETE_DIR}")
                    case $ANY in
                        yes)
                            :
                            ;;
                        no)
                            echo "ERROR: USER_CLEANINSTALL is enabled and '${INSTALLDIR}' already exists, but USER_DELETE_DIR='${USER_DELETE_DIR}'."
                            echo "ERROR: Refusing overlay installation. Set USER_DELETE_DIR='${yes}' or choose a different USER_DIR."
                            exit 1;
                            ;;
                        *)
                            echo "ERROR: invalid USER_DELETE_DIR value '${USER_DELETE_DIR}'. Use '${yes}' or '${no}'."
                            exit 1;
                            ;;
                    esac
                    ;;
                no)
                    :
                    ;;
                *)
                    echo "ERROR: invalid USER_CLEANINSTALL value '${USER_CLEANINSTALL}'. Use '${yes}' or '${no}'."
                    exit 1;
                    ;;
            esac
        fi

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
                UpdateStopWAZUH
                rm -rf -- "$INSTALLDIR"
                if [ $? -ne 0 ]; then
                    echo "Error deleting ${INSTALLDIR}"
                    exit 2;
                fi
                ;;
        esac
    fi
}

##########
# AddPFTable()
##########
AddPFTable()
{
    # Default PF table/rules snippet.
    TABLE="wazuh_fwtable"

    # Print rules to be added by the user.
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

setDefaultRuntimeOptions()
{
    # Apply installer defaults only when values are not preloaded.
    if [ "X${USER_LANGUAGE}" = "X" ]; then
        USER_LANGUAGE="en"
    fi
}

normalizeYesNo()
{
    _raw_value=$(echo "${1}" | tr '[:upper:]' '[:lower:]')

    case $_raw_value in
        $yes|$yesmatch)
            echo "yes"
            ;;
        $no|$nomatch)
            echo "no"
            ;;
        *)
            echo "invalid"
            ;;
    esac
}

normalizeYesNoOrDefault()
{
    _raw_value="$1"
    _default_value="$2"
    _normalized_value=$(normalizeYesNo "${_raw_value}")

    if [ "X${_normalized_value}" = "Xinvalid" ]; then
        echo "${_default_value}"
    else
        echo "${_normalized_value}"
    fi
}

setToggleVar()
{
    _target_var="$1"
    _input_value="$2"
    _default_value="$3"
    _normalized_value=$(normalizeYesNoOrDefault "${_input_value}" "${_default_value}")

    if [ "X${_normalized_value}" = "Xno" ]; then
        eval "${_target_var}=\"no\""
    else
        eval "${_target_var}=\"yes\""
    fi
}

setDefaultIfEmpty()
{
    _var_name="$1"
    _default_value="$2"
    eval "_current_value=\${${_var_name}}"

    if [ "X${_current_value}" = "X" ]; then
        eval "${_var_name}=\"${_default_value}\""
    fi
}

setDefaultConfigByInstallType()
{
    # Defaults shared by all install types.
    setDefaultIfEmpty USER_ENABLE_ACTIVE_RESPONSE "y"
    setDefaultIfEmpty USER_CA_STORE "n"

    if [ "X${INSTYPE}" = "Xmanager" ]; then
        setDefaultIfEmpty USER_AUTO_START "y"
        setDefaultIfEmpty USER_ENABLE_AUTHD "y"
        setDefaultIfEmpty USER_ENABLE_SYSCHECK "n"
        setDefaultIfEmpty USER_ENABLE_ROOTCHECK "n"
        setDefaultIfEmpty USER_ENABLE_SYSCOLLECTOR "n"
        setDefaultIfEmpty USER_ENABLE_SCA "n"
        setDefaultIfEmpty USER_ENABLE_UPDATE_CHECK "y"
        setDefaultIfEmpty USER_CREATE_SSL_CERT "y"
        return 0;
    fi

    if [ "X${INSTYPE}" = "Xagent" ]; then
        # Preserve current agent defaults without extra prompts.
        setDefaultIfEmpty USER_ENABLE_SYSCHECK "y"
        setDefaultIfEmpty USER_ENABLE_ROOTCHECK "y"
        setDefaultIfEmpty USER_ENABLE_SYSCOLLECTOR "y"
        setDefaultIfEmpty USER_ENABLE_SCA "y"
    fi
}

shouldUseBriefInstallFlow()
{
    [ "X${update_only}" = "X" ]
}

selectInstallType()
{
    while :; do
        echo ""
        echo "1- Installation type:"
        echo "   1) manager"
        echo "   2) agent"
        $ECHO "   Select an option [1-2]: "
        read ANSWER

        case "$ANSWER" in
            1|manager|m|${server}|${serverm})
                INSTYPE="manager"
                echo ""
                echo "  - ${serverchose}."
                return 0;
                ;;
            2|agent|a|${agent}|${agentm})
                INSTYPE="agent"
                echo ""
                echo "  - ${clientchose}."
                return 0;
                ;;
            *)
                echo ""
                echo "  - Please choose a valid option (1 or 2)."
                ;;
        esac
    done
}

resolveCleanInstallDirectory()
{
    # USER_UPDATE="n" always exits, matching previous install.sh semantics.
    echo ""
    echo "${mustuninstall}"
    exit 0;
}

detectPreinstalledDirForInstallType()
{
    PREINSTALLEDDIR=""
    PREINSTALL_DETECTION_ERROR=""
    PREINSTALL_DETECTED_TYPE=""

    getPreinstalledDirByType
    GET_PREINSTALLED_DIR_RESULT=$?
    if [ ${GET_PREINSTALLED_DIR_RESULT} -eq 2 ]; then
        return 2
    fi
    if [ ${GET_PREINSTALLED_DIR_RESULT} -ne 0 ]; then
        return 0
    fi

    if ! isWazuhInstalled "$PREINSTALLEDDIR"; then
        PREINSTALL_DETECTION_ERROR="A ${pidir_service_name} service entry points to '${PREINSTALLEDDIR}', but no Wazuh control binary was found there."
        return 2
    fi

    PRE_TYPE=$(getPreinstalledType)
    if [ "X$PRE_TYPE" = "X" ]; then
        PREINSTALL_DETECTION_ERROR="A Wazuh control binary was found in '${PREINSTALLEDDIR}', but its installation type could not be determined."
        return 2
    fi
    PREINSTALL_DETECTED_TYPE="${PRE_TYPE}"

    if [ "X$INSTYPE" = "Xagent" ] && [ "X$PRE_TYPE" != "Xagent" ]; then
        PREINSTALL_DETECTION_ERROR="The installation found at '${PREINSTALLEDDIR}' reports type '${PRE_TYPE}', which is incompatible with the selected '${INSTYPE}' installation flow."
        return 2
    fi

    if [ "X$INSTYPE" != "Xagent" ] && [ "X$PRE_TYPE" != "Xmanager" ]; then
        PREINSTALL_DETECTION_ERROR="The installation found at '${PREINSTALLEDDIR}' reports type '${PRE_TYPE}', which is incompatible with the selected '${INSTYPE}' installation flow."
        return 2
    fi
}

abortInconsistentPreinstalledInstall()
{
    echo ""
    echo "ERROR: An inconsistent existing ${INSTYPE} installation was detected."
    if [ "X${PREINSTALLEDDIR}" != "X" ]; then
        echo "Path found: ${PREINSTALLEDDIR}"
    fi
    if [ "X${PREINSTALL_DETECTED_TYPE}" != "X" ]; then
        echo "Reported type: ${PREINSTALL_DETECTED_TYPE}"
    fi
    if [ "X${PREINSTALL_DETECTION_ERROR}" != "X" ]; then
        echo "Details: ${PREINSTALL_DETECTION_ERROR}"
    fi
    echo ""
    echo "Resolve or remove the broken installation before running install.sh again."
    exit 1
}

resolveExistingInstallAction()
{
    if [ "X${USER_UPDATE}" = "X" ]; then
        while :; do
            echo ""
            echo "2- Existing ${INSTYPE} installation detected at:"
            echo "   ${PREINSTALLEDDIR}"
            echo "   1) Update existing installation"
            echo "   2) Clean install in same directory (existing data will be removed)"
            echo "   3) Exit"
            $ECHO "   Select an option [1-3]: "
            read ANY

            case "$ANY" in
                1)
                    update_only="yes"
                    break;
                    ;;
                2)
                    update_only=""
                    USER_DIR="${PREINSTALLEDDIR}"
                    USER_DELETE_DIR="y"
                    break;
                    ;;
                3)
                    echo ""
                    echo "${mustuninstall}"
                    exit 0;
                    ;;
                *)
                    echo ""
                    echo "  - Please choose a valid option (1, 2 or 3)."
                    ;;
            esac
        done
        return 0
    fi

    ANY=$(normalizeYesNo "${USER_UPDATE}")
    case $ANY in
        yes)
            update_only="yes"
            ;;
        no)
            update_only=""
            resolveCleanInstallDirectory
            ;;
        *)
            echo "ERROR: invalid USER_UPDATE value '${USER_UPDATE}'. Use '${yes}' or '${no}'."
            exit 1;
            ;;
    esac
}

validateUpgradeCompatibility()
{
    if [ -z "$USER_OLD_VERSION" ]; then
        return 0
    fi

    OLD_MAJOR=$(echo "$USER_OLD_VERSION" | sed 's/^v//' | cut -d. -f1)
    OLD_MINOR=$(echo "$USER_OLD_VERSION" | sed 's/^v//' | cut -d. -f2)

    UPGRADE_BLOCKED="no"
    ERROR_MESSAGE=""

    if [ "$USER_INSTALL_TYPE" = "agent" ]; then
        # Agent upgrades are supported only from >= 4.14.0.
        if [ -n "$OLD_MAJOR" ] && [ -n "$OLD_MINOR" ]; then
            if [ "$OLD_MAJOR" -lt 4 ] || { [ "$OLD_MAJOR" -eq 4 ] && [ "$OLD_MINOR" -lt 14 ]; }; then
                UPGRADE_BLOCKED="yes"
                ERROR_MESSAGE="Current version: $USER_OLD_VERSION
Target version:  5.0.0

Upgrade to Wazuh 5.0.0 is only supported from version 4.14.0 or later."
            fi
        fi
    else
        # Manager upgrades from 4.x to 5.x are blocked.
        if [ -n "$OLD_MAJOR" ] && [ "$OLD_MAJOR" -lt 5 ]; then
            UPGRADE_BLOCKED="yes"
            ERROR_MESSAGE="Current version: $USER_OLD_VERSION
Target version:  5.0.0

Upgrade to Wazuh 5.0.0 is not supported from version 4.x.
A clean installation is required for managers."
        fi
    fi

    if [ "$UPGRADE_BLOCKED" = "yes" ]; then
        echo ""
        echo "═════════════════════════════════════════════════════════════════"
        echo "  UPGRADE BLOCKED: Incompatible version detected"
        echo "═════════════════════════════════════════════════════════════════"
        echo ""
        echo "$ERROR_MESSAGE"
        echo ""
        echo "Required action:"
        if [ "$USER_INSTALL_TYPE" = "agent" ]; then
            echo "  1. Upgrade to version 4.14.0 or later first"
            echo "  2. Then upgrade to 5.0.0"
        else
            echo "  1. Backup your configuration"
            echo "  2. Perform a clean installation of 5.0.0"
            echo "  3. Restore your configuration"
        fi
        echo ""
        echo "For more information, visit:"
        echo "  https://documentation.wazuh.com/current/upgrade-guide/"
        echo "═════════════════════════════════════════════════════════════════"
        echo ""
        exit 1
    fi
}

prepareUpdateState()
{
    if [ "X${update_only}" != "Xyes" ]; then
        return 0
    fi

    if [ "$(doUpdatecleanup)" = "${FALSE}" ]; then
        echo ""
        echo "${unabletoupdate}"
        sleep 5
        update_only=""
        return 0
    fi

    USER_DIR="$PREINSTALLEDDIR"
    USER_INSTALL_TYPE=$(getPreinstalledType)
    USER_OLD_VERSION=$(getPreinstalledVersion)
    USER_OLD_NAME=$(getPreinstalledName)

    if [ "X${USER_INSTALL_TYPE}" = "X" ]; then
        USER_INSTALL_TYPE="${INSTYPE}"
    fi

    validateUpgradeCompatibility
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

    # Load preloaded vars, if present.
    if [ "$(isFile "${PREDEF_FILE}")" != "${FALSE}" ]; then
        . "${PREDEF_FILE}"
    fi

    setDefaultRuntimeOptions

    # Apply USER_LANGUAGE; fallback to english if locale is unavailable.
    if [ -d "${TEMPLATE}/${USER_LANGUAGE}" ]; then
        LANGUAGE=${USER_LANGUAGE}
    else
        LANGUAGE="en"
    fi

    . ./src/init/language.sh
    . ./src/init/init.sh
    . ./src/init/wazuh/wazuh.sh
    . "${TEMPLATE}/${LANGUAGE}/messages.txt"
    . ./src/init/inst-functions.sh
    . ./src/init/template-select.sh

    # Sanity checks.
    if [ "$(isFile "${VERSION_FILE}")" = "${FALSE}" ]; then
        catError "0x1-location";
    fi

    if [ ! "X$ME" = "Xroot" ]; then
        catError "0x2-beroot";
    fi

    # Installer banner.
    echo " $NAME $VERSION (Rev. $REVISION) ${installscript} - https://www.wazuh.com"
    catMsg "0x101-initial"
    echo ""
    echo "  - $system: $UNAME (${DIST_NAME} ${DIST_VER}.${DIST_SUBVER})"
    echo "  - $user: $ME"
    echo "  - $host: $HOST"
    echo ""
    echo ""

    . ./src/init/update.sh

    # Select install type.
    serverm=$(echo "${server}" | cut -b 1)
    agentm=$(echo "${agent}" | cut -b 1)

    # Skip prompt when USER_INSTALL_TYPE is preloaded.
    if [ "X${USER_INSTALL_TYPE}" = "X" ]; then
        selectInstallType
    else
        INSTYPE=${USER_INSTALL_TYPE}
    fi

    INSTYPE=$(echo "${INSTYPE}" | tr '[:upper:]' '[:lower:]')
    case "${INSTYPE}" in
        m|manager|server)
            INSTYPE="manager"
            ;;
        a|agent)
            INSTYPE="agent"
            ;;
        *)
            echo "ERROR: invalid USER_INSTALL_TYPE value '${USER_INSTALL_TYPE}'. Use 'manager' or 'agent'."
            exit 1;
            ;;
    esac

    setDefaultConfigByInstallType

    # Detect existing install of the selected type and resolve update/clean flow.
    CLEANINSTALL_ANY=$(normalizeYesNo "${USER_CLEANINSTALL}")
    if [ "X${USER_CLEANINSTALL}" = "X" ] || [ "X${CLEANINSTALL_ANY}" = "Xno" ]; then
        if [ "X$INSTYPE" = "Xagent" ]; then
            pidir_service_name="wazuh-agent"
        else
            pidir_service_name="wazuh-manager"
        fi

        detectPreinstalledDirForInstallType
        DETECT_PREINSTALLED_RESULT=$?

        if [ ${DETECT_PREINSTALLED_RESULT} -eq 2 ]; then
            abortInconsistentPreinstalledInstall
        fi

        if [ "X$PREINSTALLEDDIR" != "X" ]; then
            resolveExistingInstallAction
            prepareUpdateState
        else
            echo ""
            echo "2- Clean install: no existing ${INSTYPE} installation detected."
        fi
    elif [ "X${CLEANINSTALL_ANY}" = "Xyes" ]; then
        if [ "X${USER_UPDATE}" != "X" ]; then
            echo "WARNING: USER_UPDATE is ignored when USER_CLEANINSTALL='${yes}'."
        fi
    else
        echo "ERROR: invalid USER_CLEANINSTALL value '${USER_CLEANINSTALL}'. Use '${yes}' or '${no}'."
        exit 1;
    fi

    # Set default install dir only when USER_DIR is not provided.
    if [ -z "${USER_DIR}" ]; then
        if [ "X$INSTYPE" = "Xagent" ]; then
            INSTALLDIR="/var/ossec"
        else
            INSTALLDIR="/var/wazuh-manager"
        fi
    fi

    # Resolve install directory and environment.
    setInstallDir
    setEnv

    # Optionally remove existing directory.
    askForDelete

    INSTALLER_BRIEF_FLOW="no"
    if shouldUseBriefInstallFlow; then
        INSTALLER_BRIEF_FLOW="yes"
    fi

    # Run install-type specific configuration.
    if [ "X${update_only}" = "X" ]; then
        if [ "X$INSTYPE" = "Xmanager" ]; then
            ConfigureServer
        elif [ "X$INSTYPE" = "Xagent" ]; then
            ConfigureClient
        else
            catError "0x4-installtype"
        fi
    fi

    # Install selected components.
    Install

    # Post-install usage hints.
    control_script="wazuh-control"
    if [ "X$INSTYPE" = "Xmanager" ]; then
        control_script="wazuh-manager-control"
    fi
    echo ""
    echo " - ${configurationdone}."
    echo ""
    echo " - ${tostart}:"
    echo "      $INSTALLDIR/bin/${control_script} start"
    echo ""
    echo " - ${tostop}:"
    echo "      $INSTALLDIR/bin/${control_script} stop"
    echo ""
    echo " - ${configat} $INSTALLDIR/etc/${WAZUH_CONF}"
    echo ""
    if [ "X${INSTALLER_BRIEF_FLOW}" != "Xyes" ]; then
        catMsg "0x103-thanksforusing"
    fi


    if [ "X${update_only}" = "Xyes" ]; then
        # Update completion message.
        if isPFFirewall; then
            AddPFTable
        fi
        echo ""

        # Compatibility note for very old versions.
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


    # PF firewall reminder.
    if isPFFirewall; then
        AddPFTable
    fi


    if [ "X$INSTYPE" = "Xmanager" ]; then
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
        echo "      $INSTALLDIR/bin/${control_script} start"
        echo ""
    fi
}

_f_cfg="./install.cfg.sh"

if [ -f "$_f_cfg" ]; then
  . "$_f_cfg"
fi

# Run main installer flow.
main

exit 0

# End of script.
