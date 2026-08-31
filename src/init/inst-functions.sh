#!/bin/sh

# Wazuh Installer Functions
# Copyright (C) 2015, Wazuh Inc.
# November 18, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# File dependencies:
# ./src/init/shared.sh
# ./src/init/template-select.sh

## Templates
. ./src/init/template-select.sh

HEADER_TEMPLATE="./etc/templates/config/generic/header-comments.template"
GLOBAL_TEMPLATE="./etc/templates/config/generic/global.template"
LOGGING_TEMPLATE="./etc/templates/config/generic/logging.template"

LOCALFILES_TEMPLATE="./etc/templates/config/generic/localfile-logs/*.template"

AUTH_TEMPLATE="./etc/templates/config/generic/auth.template"
CLUSTER_TEMPLATE="./etc/templates/config/generic/cluster.template"

VULN_TEMPLATE="./etc/templates/config/generic/wodle-vulnerability-detection.manager.template"
INDEXER_TEMPLATE="./etc/templates/config/generic/wodle-indexer.manager.template"

SECURITY_CONFIGURATION_ASSESSMENT_TEMPLATE="./etc/templates/config/generic/sca.template"

##########
# WriteSyscheck()
##########
WriteSyscheck()
{
    # Adding to the config file
    if [ "X$SYSCHECK" = "Xyes" ]; then
      SYSCHECK_TEMPLATE=$(GetTemplate "syscheck.$1.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      if [ "$SYSCHECK_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
        SYSCHECK_TEMPLATE=$(GetTemplate "syscheck.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      fi
      cat ${SYSCHECK_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    else
      if [ "$1" = "manager" ]; then
        echo "  <syscheck>" >> $NEWCONFIG
        echo "    <disabled>yes</disabled>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
        echo "  </syscheck>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
      else
        echo "  <syscheck>" >> $NEWCONFIG
        echo "    <disabled>yes</disabled>" >> $NEWCONFIG
        echo "  </syscheck>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
      fi
    fi
}

##########
# DisableAuthd()
##########
DisableAuthd()
{
    echo "  <!-- Configuration for wazuh-manager-authd -->" >> $NEWCONFIG
    echo "  <auth>" >> $NEWCONFIG
    echo "    <disabled>yes</disabled>" >> $NEWCONFIG
    echo "    <port>1515</port>" >> $NEWCONFIG
    echo "    <use_source_ip>no</use_source_ip>" >> $NEWCONFIG
    echo "    <purge>yes</purge>" >> $NEWCONFIG
    echo "    <use_password>no</use_password>" >> $NEWCONFIG
    echo "    <ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256</ciphers>" >> $NEWCONFIG
    echo "    <!-- <ssl_agent_ca></ssl_agent_ca> -->" >> $NEWCONFIG
    echo "    <ssl_verify_host>no</ssl_verify_host>" >> $NEWCONFIG
    # Unified manager certificate (see GenerateHttpsManagerCert()): authd no longer generates or
    # owns its own cert/key pair, so even in this <disabled>yes</disabled> block these point at
    # remoted's, keeping the value valid in the (rare) case an operator later flips <disabled> back
    # to "no" by hand instead of regenerating the whole file. Same custom-certificate override as
    # the enabled path (see WriteAuthd's AUTH_TEMPLATE substitution above), for the same reason.
    echo "    <ssl_manager_cert>${WAZUH_REMOTE_HTTPS_CERTIFICATE:-etc/certs/remoted.pem}</ssl_manager_cert>" >> $NEWCONFIG
    echo "    <ssl_manager_key>${WAZUH_REMOTE_HTTPS_KEY:-etc/certs/remoted-key.pem}</ssl_manager_key>" >> $NEWCONFIG
    echo "  </auth>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG
}

##########
# WriteRootcheck()
##########
WriteRootcheck()
{
    # Adding to the config file
    if [ "X$ROOTCHECK" = "Xyes" ]; then
      ROOTCHECK_TEMPLATE=$(GetTemplate "rootcheck.$1.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      if [ "$ROOTCHECK_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
        ROOTCHECK_TEMPLATE=$(GetTemplate "rootcheck.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      fi
      sed -e "s|\${INSTALLDIR}|$INSTALLDIR|g" "${ROOTCHECK_TEMPLATE}" >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    else
      echo "  <rootcheck>" >> $NEWCONFIG
      echo "    <disabled>yes</disabled>" >> $NEWCONFIG
      echo "  </rootcheck>" >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
}

##########
# Syscollector()
##########
WriteSyscollector()
{
    # Adding to the config file
    if [ "X$SYSCOLLECTOR" = "Xyes" ]; then
      SYSCOLLECTOR_TEMPLATE=$(GetTemplate "wodle-syscollector.$1.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      if [ "$SYSCOLLECTOR_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
        SYSCOLLECTOR_TEMPLATE=$(GetTemplate "wodle-syscollector.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      fi
      cat ${SYSCOLLECTOR_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
}

##########
# WriteConfigurationAssessment()
##########
WriteConfigurationAssessment()
{
    # Adding to the config file
    if [ "X$SECURITY_CONFIGURATION_ASSESSMENT" = "Xyes" ]; then
      SECURITY_CONFIGURATION_ASSESSMENT_TEMPLATE=$(GetTemplate "sca.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      cat ${SECURITY_CONFIGURATION_ASSESSMENT_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
}

##########
# InstallSecurityConfigurationAssessmentFiles()
##########
InstallSecurityConfigurationAssessmentFiles()
{

    cd ..

    CONFIGURATION_ASSESSMENT_FILES_PATH=$(GetTemplate "sca.files" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    cd ./src
    if [ "$CONFIGURATION_ASSESSMENT_FILES_PATH" = "ERROR_NOT_FOUND" ]; then
        echo "SCA policies are not available for this OS version ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER}."
    else
        echo "Removing old SCA policies..."
        rm -f ${INSTALLDIR}/ruleset/sca/*

        echo "Installing SCA policies..."
        CONFIGURATION_ASSESSMENT_FILES=$(cat .$CONFIGURATION_ASSESSMENT_FILES_PATH)
        for FILE in $CONFIGURATION_ASSESSMENT_FILES; do
            if [ -f "../ruleset/sca/$FILE" ]; then
                ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../ruleset/sca/$FILE ${INSTALLDIR}/ruleset/sca
            else
                echo "ERROR: SCA policy not found: ../ruleset/sca/$FILE"
            fi
        done
    fi
}

##########
# GenerateHttpsManagerCert()
##########
# Self-signed certificate for the HTTPS agent server (remoted_module). Manager
# only -- the listener doesn't exist on agents. Uses wazuh-manager-remoted's own
# -C/-B/-K/-X/-S flags (same generate_cert() used for authd's cert/key, now in
# shared/). This is now the manager's ONLY self-signed cert/key pair: authd no
# longer generates or owns one of its own (its <ssl_manager_cert>/<ssl_manager_key>
# point here too -- see auth.template and DisableAuthd() above), since /enroll's
# mTLS mode treats "this certificate validated" as the enrollment credential and
# both listeners must therefore present the same manager identity.
GenerateHttpsManagerCert()
{
    if [ "X${INSTYPE}" = "Xagent" ]; then
        return
    fi

    # Custom certificate/key paths supplied through the WAZUH_REMOTE_HTTPS_*
    # installation variables mean the admin manages these files: nothing to
    # generate at the default location.
    if [ -n "${WAZUH_REMOTE_HTTPS_CERTIFICATE}" ] || [ -n "${WAZUH_REMOTE_HTTPS_KEY}" ]; then
        return
    fi

    if [ "X$SSL_CERT" = "Xyes" ]; then
        # Unified certificate directory: root-owned and sticky (drwxrwx--T). The server
        # daemons run as ${WAZUH_USER} and regenerate their own self-signed certs here
        # (group write), while the sticky bit keeps them from replacing the root-owned
        # indexer trust material that shares the directory. Created here (rather than in a
        # separate authd-specific step, now removed) since this is the first cert-generating
        # step that runs on a manager install.
        ${INSTALL} -d -m 1770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/certs

        # Generation auto-signed certificate if not exists
        if [ ! -f "${INSTALLDIR}/etc/certs/remoted-key.pem" ] && [ ! -f "${INSTALLDIR}/etc/certs/remoted.pem" ]; then
            if [ ! "X${USER_GENERATE_AUTHD_CERT}" = "Xn" ]; then
                    echo "Generating self-signed certificate for the HTTPS agent server..."
                    ${INSTALLDIR}/bin/wazuh-manager-remoted -C 365 -B 2048 -K ${INSTALLDIR}/etc/certs/remoted-key.pem -X ${INSTALLDIR}/etc/certs/remoted.pem -S "/C=US/ST=California/CN=wazuh/"
            fi
        fi

        # Owned by ${WAZUH_USER}: remoted drops to that user and regenerates these files at
        # runtime. Re-applied unconditionally so upgrades from installs that left them
        # root-owned also get corrected.
        if [ -f "${INSTALLDIR}/etc/certs/remoted-key.pem" ] && [ -f "${INSTALLDIR}/etc/certs/remoted.pem" ]; then
            chown ${WAZUH_USER}:${WAZUH_GROUP} ${INSTALLDIR}/etc/certs/remoted-key.pem
            chown ${WAZUH_USER}:${WAZUH_GROUP} ${INSTALLDIR}/etc/certs/remoted.pem
            chmod 640 ${INSTALLDIR}/etc/certs/remoted-key.pem
            chmod 640 ${INSTALLDIR}/etc/certs/remoted.pem
        fi
    fi
}

##########
# SetIndexerCertsOwnership()
##########
# etc/certs holds two kinds of material: the server certificates each daemon self-generates
# (owned by ${WAZUH_USER}, since the daemon must write them) and the indexer trust material
# provisioned externally (root-owned, the manager only reads it). The directory is root-owned
# and sticky so the daemons can (re)generate their own certs but cannot replace the root-owned
# indexer material; the indexer certs are group-readable by ${WAZUH_GROUP} so the engine and
# the framework read them after dropping privileges. Applied unconditionally so upgrades and
# re-runs correct earlier ownerships.
SetIndexerCertsOwnership()
{
    if [ "X${INSTYPE}" = "Xagent" ]; then
        return
    fi

    ${INSTALL} -d -m 1770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/certs
    chown root:${WAZUH_GROUP} ${INSTALLDIR}/etc/certs
    chmod 1770 ${INSTALLDIR}/etc/certs
    for CERT_FILE in root-ca.pem indexer-connector.pem indexer-connector-key.pem; do
        if [ -f "${INSTALLDIR}/etc/certs/${CERT_FILE}" ]; then
            chown root:${WAZUH_GROUP} ${INSTALLDIR}/etc/certs/${CERT_FILE}
            chmod 640 ${INSTALLDIR}/etc/certs/${CERT_FILE}
        fi
    done
}

##########
# WriteLogs()
##########
WriteLogs()
{
  MODE="$1"
  LOCALFILES_TMP=`cat ${LOCALFILES_TEMPLATE}`
  HAS_JOURNALD=`command -v journalctl`

  # If journald is available, add it to the generated configuration.
  if [ "X$HAS_JOURNALD" != "X" ] && [ "$MODE" = "add" ]; then
    echo "  <localfile>" >> $NEWCONFIG
    echo "    <log_format>journald</log_format>" >> $NEWCONFIG
    echo "    <location>journald</location>" >> $NEWCONFIG
    echo "  </localfile>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG
  fi

  OLD_IFS="$IFS"  # Save the current IFS
  IFS='
'

  for i in ${LOCALFILES_TMP}; do
      field1=$(echo $i | cut -d\: -f1)
      field2=$(echo $i | cut -d\: -f2)
      field3=$(echo $i | cut -d\: -f3)
      if [ "X$field1" = "Xskip_check_exist" ]; then
          SKIP_CHECK_FILE="yes"
          LOG_FORMAT="$field2"
          FILE="$field3"
      else
          SKIP_CHECK_FILE="no"
          LOG_FORMAT="$field1"
          FILE="$field2"
      fi

      # Check installation directory
      if [ $(echo $FILE | grep "INSTALL_DIR") ]; then
        FILE=$(echo $FILE | sed -e "s|INSTALL_DIR|${INSTALLDIR}|g")
      fi

      # If journald is not available, change the log_format from '[!journald] ${log_type}' to '${log_type}'
      NEGATE_JOURNALD=$(echo "$LOG_FORMAT" | grep "\[!journald\] ")
      if [ "X$HAS_JOURNALD" = "X" ]; then
        if [ -n "$NEGATE_JOURNALD" ]; then
          LOG_FORMAT=$(echo "$LOG_FORMAT" | sed -e "s|\[!journald\] ||g")
        fi
      # If journald is available, skip if LOG_FORMAT start with '[!journald]'
      else
        if [ -n "$NEGATE_JOURNALD" ]; then
          continue
        fi
      fi

      # If log file present or skip file
      if [ -f "$FILE" ] || [ "X$SKIP_CHECK_FILE" = "Xyes" ]; then
        # Print
        if [ "$MODE" = "echo" ]; then
            case "$FILE" in
                */logs/active-responses.log|/var/log/dpkg.log)
                    ;;
                *)
                    echo "    -- $FILE"
                    ;;
            esac
        # Add to the configuration file
        elif [ "$MODE" = "add" ]; then
          echo "  <localfile>" >> $NEWCONFIG
          if [ "$FILE" = "snort" ]; then
            head -n 1 $FILE|grep "\[**\] "|grep -v "Classification:" > /dev/null
            if [ $? = 0 ]; then
              echo "    <log_format>snort-full</log_format>" >> $NEWCONFIG
            else
              echo "    <log_format>snort-fast</log_format>" >> $NEWCONFIG
            fi
          else
            echo "    <log_format>$LOG_FORMAT</log_format>" >> $NEWCONFIG
          fi
          echo "    <location>$FILE</location>" >>$NEWCONFIG
          echo "  </localfile>" >> $NEWCONFIG
          echo "" >> $NEWCONFIG
        fi
      fi
  done
  IFS="$OLD_IFS"  # Restore the IFS
}

##########
# SetHeaders() 1-agent|manager
##########
SetHeaders()
{
    HEADERS_TMP="/tmp/wazuh-headers.tmp"
    if [ "$DIST_VER" = "0" ]; then
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION//g" "$HEADER_TEMPLATE" > $HEADERS_TMP
    else
      if [ "$DIST_SUBVER" = "0" ]; then
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION/${DIST_VER}/g" "$HEADER_TEMPLATE" > $HEADERS_TMP
      else
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION/${DIST_VER}.${DIST_SUBVER}/g" "$HEADER_TEMPLATE" > $HEADERS_TMP
      fi
    fi
    cat $HEADERS_TMP
    rm -f $HEADERS_TMP
}

##########
# GenerateService() $1=template
##########
GenerateService()
{
    SERVICE_TEMPLATE=./src/init/templates/${1}
    if [ "X${INSTYPE}" = "Xmanager" ]; then
        sed -e "s|WAZUH_HOME_TMP|${INSTALLDIR}|g" \
            -e "s|/bin/wazuh-control|/bin/wazuh-manager-control|g" \
            ${SERVICE_TEMPLATE}
    else
        sed "s|WAZUH_HOME_TMP|${INSTALLDIR}|g" ${SERVICE_TEMPLATE}
    fi
}

##########
# ParseManagerEndpoint() $1=WAZUH_MANAGER_ENDPOINT's value
#
# Splits the combined connection target (#38624) into MEP_HOST / MEP_PORT /
# MEP_ENDPOINT, the three tags the agent still reads:
#
#   [https://] host [:port] [/[prefix]]
#
# Only the host is mandatory. Note that "no '/' at all" means "default prefix" while
# "a trailing '/' with nothing after it" is the deliberate opt-out (#38614) and must
# come out as an empty <endpoint></endpoint>.
#
# Byte-for-byte the same logic as parse_manager_endpoint() in
# register_configure_agent.sh and ParseManagerEndpoint() in
# src/win32/InstallerScripts.vbs -- a change in one belongs in all three. It is
# duplicated rather than shared because register_configure_agent.sh ships inside the
# packages and cannot source this file (the relative . ./src/init/template-select.sh
# here assumes a repo checkout at CWD, which a post-install script does not have).
##########
DEFAULT_MANAGER_PORT="1517"
DEFAULT_MANAGER_ENDPOINT="/wazuh-manager/"

ParseManagerEndpoint()
{
    mep_raw="$1"
    mep_rest="$mep_raw"
    MEP_HOST=""
    MEP_PORT="${DEFAULT_MANAGER_PORT}"
    MEP_ENDPOINT="${DEFAULT_MANAGER_ENDPOINT}"

    if [ "X${mep_raw}" = "X" ]; then
        echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': a manager address is required." >&2
        return 1
    fi

    case "${mep_rest}" in
        *"://"*)
            mep_scheme="${mep_rest%%://*}"
            case "${mep_scheme}" in
                */*) ;;
                *)
                    mep_rest="${mep_rest#*://}"
                    case "${mep_scheme}" in
                        [Hh][Tt][Tt][Pp][Ss]) ;;
                        *)
                            echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': unsupported scheme '${mep_scheme}://'; only https is served." >&2
                            return 1
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac

    case "${mep_rest}" in
        */*)
            mep_authority="${mep_rest%%/*}"
            mep_path="${mep_rest#*/}"
            mep_path_given="yes"
            ;;
        *)
            mep_authority="${mep_rest}"
            mep_path=""
            mep_path_given="no"
            ;;
    esac

    mep_port_given=""
    case "${mep_authority}" in
        "["*)
            case "${mep_authority}" in
                *"]"*) ;;
                *)
                    echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': unterminated '[' in the address; a bracketed IPv6 literal needs a closing ']'." >&2
                    return 1
                    ;;
            esac
            MEP_HOST="${mep_authority#[}"
            MEP_HOST="${MEP_HOST%%]*}"
            mep_after="${mep_authority#*]}"
            case "${mep_after}" in
                "") ;;
                ":"*) mep_port_given="${mep_after#:}" ;;
                *)
                    echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': unexpected '${mep_after}' after the bracketed address." >&2
                    return 1
                    ;;
            esac
            # A zone id (%25<iface>) stays part of the host: the agent resolves it
            # with if_nametoindex() at startup (#38624).
            ;;
        *:*:*)
            echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': an IPv6 address must be bracketed, e.g. [2001:db8::1]:${DEFAULT_MANAGER_PORT}." >&2
            return 1
            ;;
        *:*)
            MEP_HOST="${mep_authority%:*}"
            mep_port_given="${mep_authority##*:}"
            ;;
        *)
            MEP_HOST="${mep_authority}"
            ;;
    esac

    if [ "X${MEP_HOST}" = "X" ]; then
        echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': a manager address is required." >&2
        return 1
    fi

    if [ "X${mep_port_given}" != "X" ]; then
        case "${mep_port_given}" in
            ''|*[!0-9]*)
                echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': port '${mep_port_given}' is not a number." >&2
                return 1
                ;;
        esac
        if [ "${mep_port_given}" -lt 1 ] || [ "${mep_port_given}" -gt 65535 ]; then
            echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': port '${mep_port_given}' is outside 1-65535." >&2
            return 1
        fi
        MEP_PORT="${mep_port_given}"
    elif [ "${mep_authority}" != "${mep_authority%:}" ]; then
        echo "Invalid WAZUH_MANAGER_ENDPOINT '${mep_raw}': trailing ':' with no port." >&2
        return 1
    fi

    if [ "${mep_path_given}" = "yes" ]; then
        while : ; do
            case "${mep_path}" in
                /*) mep_path="${mep_path#/}" ;;
                *) break ;;
            esac
        done
        while : ; do
            case "${mep_path}" in
                */) mep_path="${mep_path%/}" ;;
                *) break ;;
            esac
        done
        if [ "X${mep_path}" = "X" ]; then
            MEP_ENDPOINT=""
        else
            MEP_ENDPOINT="/${mep_path}/"
        fi
    fi

    return 0
}

##########
# WriteAgent() $1="no_locafiles" or empty
##########
WriteAgent()
{
    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Agent")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<ossec_config>" >> $NEWCONFIG
    # <client> is renamed to <agent> in 5.x; the inner block stays <manager>.
    echo "  <agent>" >> $NEWCONFIG
    echo "    <manager>" >> $NEWCONFIG

    # <endpoint> carries the whole connection target (#38624). WAZUH_MANAGER_ENDPOINT
    # supplies it directly when set; otherwise it is composed from install.sh's own
    # $SERVER_IP/$HNAME prompt, which is the only address this path has. Tested with
    # ${VAR+x} rather than -n so an explicitly empty value is rejected instead of
    # silently read as unset: "" used to be the prefix opt-out (#38614). A rejected
    # value falls back to the prompted address, with the reason already on stderr --
    # this path must still emit a usable template, and the operator is present to see
    # the message.
    # $SERVER_IP/$HNAME come from install.sh's own prompt and are the base. WAZUH_MANAGER
    # (with WAZUH_MANAGER_PORT) still composes a value, and WAZUH_MANAGER_ENDPOINT
    # overrides everything when set.
    AGENT_ENDPOINT="$SERVER_IP"
    if [ "X${HNAME}" != "X" ]; then
      AGENT_ENDPOINT="$HNAME"
    fi

    if [ "X${WAZUH_MANAGER}" != "X" ]; then
      AGENT_ENDPOINT="${WAZUH_MANAGER}"
    fi

    # A bare IPv6 literal needs bracketing once it shares a value with the port.
    case "${AGENT_ENDPOINT}" in
      # Already bracketed values must be left alone, or "[2001:db8::1]" becomes
      # "[[2001:db8::1]]" and the agent will not start. Matches the guard in
      # InstallerScripts.vbs.
      \[*) ;;
      *:*:*) AGENT_ENDPOINT="[${AGENT_ENDPOINT}]" ;;
    esac

    if [ "X${WAZUH_MANAGER_PORT}" != "X" ]; then
      AGENT_ENDPOINT="${AGENT_ENDPOINT}:${WAZUH_MANAGER_PORT}"
    fi

    # WAZUH_MANAGER_ENDPOINT wins outright once it is set, even if it fails validation:
    # it carries the whole URL and the operator asked for it specifically, so falling back
    # to a value composed from WAZUH_MANAGER would silently point the agent at a different
    # manager. A bad value is reported here and written through, so the agent refuses it
    # loudly at startup instead -- same rule as register_configure_agent.sh and
    # InstallerScripts.vbs, which write no <manager> block at all in that case.
    if [ "X${WAZUH_MANAGER_ENDPOINT+x}" != "X" ]; then
      ParseManagerEndpoint "${WAZUH_MANAGER_ENDPOINT}"
      AGENT_ENDPOINT="${WAZUH_MANAGER_ENDPOINT}"
    fi

    echo "      <endpoint>${AGENT_ENDPOINT}</endpoint>" >> $NEWCONFIG
    echo "    </manager>" >> $NEWCONFIG
    if [ "X${USER_AGENT_CONFIG_PROFILE}" != "X" ]; then
         PROFILE=${USER_AGENT_CONFIG_PROFILE}
         echo "    <config-profile>$PROFILE</config-profile>" >> $NEWCONFIG
    else
      if [ "$DIST_VER" = "0" ]; then
        echo "    <config-profile>$DIST_NAME</config-profile>" >> $NEWCONFIG
      else
        if [ "$DIST_SUBVER" = "0" ]; then
          echo "    <config-profile>$DIST_NAME, $DIST_NAME$DIST_VER</config-profile>" >> $NEWCONFIG
        else
          echo "    <config-profile>$DIST_NAME, $DIST_NAME$DIST_VER, $DIST_NAME$DIST_VER.$DIST_SUBVER</config-profile>" >> $NEWCONFIG
        fi
      fi
    fi
    echo "  </agent>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Rootcheck
    WriteRootcheck "agent"

    # Syscollector configuration
    WriteSyscollector "agent"

    # Configuration assessment configuration
    WriteConfigurationAssessment

    # Syscheck
    WriteSyscheck "agent"

    # Write the log files
    if [ "X${NO_LOCALFILES}" = "X" ]; then
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
      WriteLogs "add"
    else
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
    fi

    # Localfile commands
    LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.agent.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_COMMANDS_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cat ${LOCALFILE_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Localfile extra
    LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.agent.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    if [ ! "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      cat ${LOCALFILE_EXTRA_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    echo "  <!-- Active response -->" >> $NEWCONFIG

    echo "  <active-response>" >> $NEWCONFIG
    if [ "X$ACTIVERESPONSE" = "Xyes" ]; then
        echo "    <disabled>no</disabled>" >> $NEWCONFIG
    else
        echo "    <disabled>yes</disabled>" >> $NEWCONFIG
    fi
    echo "    <ca_store>etc/wpk_root.pem</ca_store>" >> $NEWCONFIG

    if [ -n "$CA_STORE" ]
    then
        echo "    <ca_store>${CA_STORE}</ca_store>" >> $NEWCONFIG
    fi

    echo "    <ca_verification>yes</ca_verification>" >> $NEWCONFIG
    echo "  </active-response>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "</ossec_config>" >> $NEWCONFIG
}


##########
# Validation helpers for the WAZUH_REMOTE_* installation variables.
# Each check is skipped when the variable is empty (the default is used).
# On an invalid value the whole generation exits so that no configuration
# is ever written with a bad value.
##########
RemoteVarError()
{
    echo "ERROR: Invalid value '$2' for installation variable $1: $3" >&2
    # $NEWCONFIG is always a scratch file (./wazuh.conf.temp for the generator,
    # ./etc/wazuh.mc for install.sh), consumed only after a complete write.
    rm -f "$NEWCONFIG"
    exit 1
}

CheckRemoteXmlSafe()
{
    [ -z "$2" ] && return 0
    case "$2" in
        *[\&\<\>\"\']*)
            RemoteVarError "$1" "$2" "the characters & < > \" ' are not allowed";;
    esac
}

CheckRemotePort()
{
    [ -z "$2" ] && return 0
    case "$2" in
        *[!0-9]*)
            RemoteVarError "$1" "$2" "expected a port number (1-65535)";;
    esac
    if [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
        RemoteVarError "$1" "$2" "expected a port number (1-65535)"
    fi
}

CheckRemoteYesNo()
{
    [ -z "$2" ] && return 0
    case "$2" in
        yes|no) ;;
        *) RemoteVarError "$1" "$2" "expected 'yes' or 'no'";;
    esac
}

CheckRemoteIP()
{
    [ -z "$2" ] && return 0
    case "$2" in
        *:*)
            # IPv6: hex digits and colons only.
            case "$2" in
                *[!0-9a-fA-F:]*) RemoteVarError "$1" "$2" "expected a valid IP address";;
            esac
            ;;
        *.*.*.*)
            OLD_IFS="$IFS"; IFS='.'
            set -- "$1" "$2" $2
            IFS="$OLD_IFS"
            if [ "$#" != 6 ]; then
                RemoteVarError "$1" "$2" "expected a valid IP address"
            fi
            for OCTET in "$3" "$4" "$5" "$6"; do
                case "$OCTET" in
                    ''|*[!0-9]*) RemoteVarError "$1" "$2" "expected a valid IP address";;
                esac
                if [ "$OCTET" -gt 255 ]; then
                    RemoteVarError "$1" "$2" "expected a valid IP address"
                fi
            done
            ;;
        *) RemoteVarError "$1" "$2" "expected a valid IP address";;
    esac
}

CheckRemoteProtocol()
{
    [ -z "$2" ] && return 0
    OLD_IFS="$IFS"; IFS=','
    for PROTO_WORD in $2; do
        case "$PROTO_WORD" in
            tcp|udp) ;;
            *) IFS="$OLD_IFS"; RemoteVarError "$1" "$2" "expected 'tcp', 'udp' or a comma-separated combination";;
        esac
    done
    IFS="$OLD_IFS"
}

CheckRemoteTime()
{
    [ -z "$2" ] && return 0
    TIME_NUM=${2%%[!0-9]*}
    TIME_UNIT=${2#"$TIME_NUM"}
    if [ -z "$TIME_NUM" ] || [ "$TIME_NUM" -eq 0 ]; then
        RemoteVarError "$1" "$2" "expected a positive number with an optional time unit (s, m, h, d, w)"
    fi
    # Units as accepted by w_parse_time(): lowercase only, weeks included.
    case "$TIME_UNIT" in
        ''|[smhdw]) ;;
        *) RemoteVarError "$1" "$2" "expected a positive number with an optional time unit (s, m, h, d, w)";;
    esac
}

CheckRemoteSize()
{
    [ -z "$2" ] && return 0
    SIZE_NUM=${2%%[!0-9]*}
    SIZE_UNIT=${2#"$SIZE_NUM"}
    if [ -z "$SIZE_NUM" ] || [ "$SIZE_NUM" -eq 0 ]; then
        RemoteVarError "$1" "$2" "expected a positive size with an optional unit (B, KB, MB, GB)"
    fi
    case "$SIZE_UNIT" in
        ''|[KkMmGgBb]|[KkMmGg][Bb]) ;;
        *) RemoteVarError "$1" "$2" "expected a positive size with an optional unit (B, KB, MB, GB)";;
    esac
}

# Mirrors w_remoted_validate_global_prefix() in src/config/src/remote-config.c exactly, so a
# bad value aborts BEFORE any side effect instead of producing a configuration the service
# then refuses to start with: leading '/', charset [A-Za-z0-9._~/-] (no '%': the prefix is
# compared byte-exactly against the wire target, never percent-decoded), no empty ('//') and
# no '.'/'..' segments (proxies dot-normalize request paths), at most 255 characters.
# '/' alone is the explicit identity value (endpoints served unprefixed).
CheckRemotePrefix()
{
    [ -z "$2" ] && return 0
    case "$2" in
        /*) ;;
        *) RemoteVarError "$1" "$2" "expected a URL path starting with '/'";;
    esac
    case "$2" in
        *//*) RemoteVarError "$1" "$2" "empty path segments ('//') are not allowed";;
    esac
    case "$2" in
        *[!A-Za-z0-9._~/-]*) RemoteVarError "$1" "$2" "allowed characters are A-Z a-z 0-9 . _ ~ - /";;
    esac
    case "${2}/" in
        */./*|*/../*) RemoteVarError "$1" "$2" "'.' and '..' path segments are not allowed";;
    esac
    if [ ${#2} -gt 255 ]; then
        RemoteVarError "$1" "$2" "maximum length is 255 characters"
    fi
}

##########
# ValidateRemoteVars()
# Idempotent: install.sh validates up front, before any side effect, while the
# package flows reach it through WriteRemote().
##########
ValidateRemoteVars()
{
    if [ "X${REMOTE_VARS_VALIDATED}" = "Xyes" ]; then
        return 0
    fi
    REMOTE_VARS_VALIDATED="yes"

    for REMOTE_VAR_NAME in WAZUH_REMOTE_HTTPS_CERTIFICATE WAZUH_REMOTE_HTTPS_KEY \
                           WAZUH_REMOTE_HTTPS_CA WAZUH_REMOTE_HTTPS_CIPHERS \
                           WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX; do
        eval "REMOTE_VAR_VALUE=\${${REMOTE_VAR_NAME}}"
        CheckRemoteXmlSafe "$REMOTE_VAR_NAME" "$REMOTE_VAR_VALUE"
    done

    CheckRemotePort "WAZUH_REMOTE_HTTPS_PORT" "${WAZUH_REMOTE_HTTPS_PORT}"
    CheckRemoteIP "WAZUH_REMOTE_HTTPS_BIND_ADDR" "${WAZUH_REMOTE_HTTPS_BIND_ADDR}"
    CheckRemotePrefix "WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX" "${WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX}"
    CheckRemoteSize "WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE" "${WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE}"
    CheckRemoteYesNo "WAZUH_REMOTE_HTTPS_DUAL_STACK" "${WAZUH_REMOTE_HTTPS_DUAL_STACK}"

    case "${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}" in
        ''|none|certificate|full) ;;
        *) RemoteVarError "WAZUH_REMOTE_HTTPS_VERIFICATION_MODE" "${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}" "expected 'none', 'certificate' or 'full'";;
    esac

    # Either path alone disables the self-signed generation while the other keeps its
    # default location, which nothing creates.
    if [ -n "${WAZUH_REMOTE_HTTPS_CERTIFICATE}" ] && [ -z "${WAZUH_REMOTE_HTTPS_KEY}" ]; then
        RemoteVarError "WAZUH_REMOTE_HTTPS_CERTIFICATE" "${WAZUH_REMOTE_HTTPS_CERTIFICATE}" "WAZUH_REMOTE_HTTPS_KEY is required when a custom certificate is provided"
    fi

    if [ -n "${WAZUH_REMOTE_HTTPS_KEY}" ] && [ -z "${WAZUH_REMOTE_HTTPS_CERTIFICATE}" ]; then
        RemoteVarError "WAZUH_REMOTE_HTTPS_KEY" "${WAZUH_REMOTE_HTTPS_KEY}" "WAZUH_REMOTE_HTTPS_CERTIFICATE is required when a custom private key is provided"
    fi

    case "${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}" in
        certificate|full)
            if [ -z "${WAZUH_REMOTE_HTTPS_CA}" ]; then
                RemoteVarError "WAZUH_REMOTE_HTTPS_VERIFICATION_MODE" "${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}" "WAZUH_REMOTE_HTTPS_CA is required when certificate verification is enabled"
            fi
            ;;
    esac

    if [ -n "${WAZUH_REMOTE_HTTPS_DUAL_STACK}" ]; then
        case "${WAZUH_REMOTE_HTTPS_BIND_ADDR}" in
            *:*) ;;
            *) echo "WARNING: WAZUH_REMOTE_HTTPS_DUAL_STACK only applies to an IPv6 WAZUH_REMOTE_HTTPS_BIND_ADDR; the option will be ignored at runtime." >&2;;
        esac
    fi

    CheckRemoteYesNo "WAZUH_REMOTE_LEGACY_ENABLED" "${WAZUH_REMOTE_LEGACY_ENABLED}"
    CheckRemotePort "WAZUH_REMOTE_LEGACY_PORT" "${WAZUH_REMOTE_LEGACY_PORT}"
    CheckRemoteProtocol "WAZUH_REMOTE_LEGACY_PROTOCOL" "${WAZUH_REMOTE_LEGACY_PROTOCOL}"
    CheckRemoteYesNo "WAZUH_REMOTE_LEGACY_IPV6" "${WAZUH_REMOTE_LEGACY_IPV6}"
    CheckRemoteIP "WAZUH_REMOTE_LEGACY_LOCAL_IP" "${WAZUH_REMOTE_LEGACY_LOCAL_IP}"
    CheckRemoteTime "WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME" "${WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME}"

    case "${WAZUH_REMOTE_LEGACY_QUEUE_SIZE}" in
        '') ;;
        *[!0-9]*|0) RemoteVarError "WAZUH_REMOTE_LEGACY_QUEUE_SIZE" "${WAZUH_REMOTE_LEGACY_QUEUE_SIZE}" "expected a positive integer";;
    esac

    if [ -n "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" ]; then
        case "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" in
            *[!0-9]*) RemoteVarError "WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME" "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" "expected a number of seconds (0-3600)";;
        esac
        if [ "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" -gt 3600 ]; then
            RemoteVarError "WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME" "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" "expected a number of seconds (0-3600)"
        fi
    fi

    CheckRemoteYesNo "WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS" "${WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS}"
}

##########
# WriteRemote()
# Writes the <remote> block. Every value can be customized at installation
# time through the WAZUH_REMOTE_* variables; options with no built-in
# default are only written when their variable is set.
##########
WriteRemote()
{
    ValidateRemoteVars

    echo "  <remote>" >> $NEWCONFIG
    echo "    <https>" >> $NEWCONFIG
    echo "      <port>${WAZUH_REMOTE_HTTPS_PORT:-1517}</port>" >> $NEWCONFIG
    echo "      <bind_addr>${WAZUH_REMOTE_HTTPS_BIND_ADDR:-127.0.0.1}</bind_addr>" >> $NEWCONFIG
    echo "      <global_prefix>${WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX:-/wazuh-manager/}</global_prefix>" >> $NEWCONFIG
    echo "      <certificate>${WAZUH_REMOTE_HTTPS_CERTIFICATE:-etc/certs/remoted.pem}</certificate>" >> $NEWCONFIG
    echo "      <key>${WAZUH_REMOTE_HTTPS_KEY:-etc/certs/remoted-key.pem}</key>" >> $NEWCONFIG
    if [ -n "${WAZUH_REMOTE_HTTPS_CA}" ]; then
        echo "      <ca>${WAZUH_REMOTE_HTTPS_CA}</ca>" >> $NEWCONFIG
    fi
    if [ -n "${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}" ]; then
        echo "      <verification_mode>${WAZUH_REMOTE_HTTPS_VERIFICATION_MODE}</verification_mode>" >> $NEWCONFIG
    fi
    if [ -n "${WAZUH_REMOTE_HTTPS_CIPHERS}" ]; then
        echo "      <ciphers>${WAZUH_REMOTE_HTTPS_CIPHERS}</ciphers>" >> $NEWCONFIG
    fi
    if [ -n "${WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE}" ]; then
        echo "      <max_body_size>${WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE}</max_body_size>" >> $NEWCONFIG
    fi
    if [ -n "${WAZUH_REMOTE_HTTPS_DUAL_STACK}" ]; then
        echo "      <dual_stack>${WAZUH_REMOTE_HTTPS_DUAL_STACK}</dual_stack>" >> $NEWCONFIG
    fi
    echo "    </https>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG
    echo "    <legacy>" >> $NEWCONFIG
    echo "      <enabled>${WAZUH_REMOTE_LEGACY_ENABLED:-yes}</enabled>" >> $NEWCONFIG
    echo "      <port>${WAZUH_REMOTE_LEGACY_PORT:-1514}</port>" >> $NEWCONFIG
    echo "      <protocol>${WAZUH_REMOTE_LEGACY_PROTOCOL:-tcp}</protocol>" >> $NEWCONFIG
    if [ -n "${WAZUH_REMOTE_LEGACY_IPV6}" ]; then
        echo "      <ipv6>${WAZUH_REMOTE_LEGACY_IPV6}</ipv6>" >> $NEWCONFIG
    fi
    # With an IPv6 listener and no explicit address, local_ip is left out so
    # that remoted applies its own IPv6 default instead of 127.0.0.1.
    if [ -n "${WAZUH_REMOTE_LEGACY_LOCAL_IP}" ] || [ "X${WAZUH_REMOTE_LEGACY_IPV6}" != "Xyes" ]; then
        echo "      <local_ip>${WAZUH_REMOTE_LEGACY_LOCAL_IP:-127.0.0.1}</local_ip>" >> $NEWCONFIG
    fi
    echo "      <queue_size>${WAZUH_REMOTE_LEGACY_QUEUE_SIZE:-131072}</queue_size>" >> $NEWCONFIG
    if [ -n "${WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME}" ]; then
        echo "      <rids_closing_time>${WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME}</rids_closing_time>" >> $NEWCONFIG
    fi
    if [ -n "${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}" ]; then
        echo "      <connection_overtake_time>${WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME}</connection_overtake_time>" >> $NEWCONFIG
    fi
    echo "    </legacy>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG
    echo "    <agents>" >> $NEWCONFIG
    echo "      <allow_higher_versions>${WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS:-no}</allow_higher_versions>" >> $NEWCONFIG
    echo "    </agents>" >> $NEWCONFIG
    echo "  </remote>" >> $NEWCONFIG
}

##########
# WriteManager() $1="no_locafiles" or empty
##########
WriteManager()
{
    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Manager")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<wazuh_config>" >> $NEWCONFIG

    GLOBAL_CONTENT=$(cat ${GLOBAL_TEMPLATE})

    echo "$GLOBAL_CONTENT" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    WriteRemote
    echo "" >> $NEWCONFIG

    # Vulnerability Detector
    cat ${VULN_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Indexer
    cat ${INDEXER_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Writting auth configuration
    if [ "X${AUTHD}" = "Xyes" ]; then
        # Same custom-certificate override WriteRemote()'s <https> block already honors (see
        # GenerateHttpsManagerCert() above): authd's <ssl_manager_cert>/<ssl_manager_key> must
        # point at whatever file the manager's HTTPS listener actually loads, or authd fails to
        # start (ENOENT) whenever a custom certificate is supplied -- GenerateHttpsManagerCert()
        # correctly skips generating the default etc/certs/remoted.pem in that case, but
        # auth.template's cert paths used to stay hardcoded to it regardless.
        WAZUH_AUTHD_SSL_MANAGER_CERT="${WAZUH_REMOTE_HTTPS_CERTIFICATE:-etc/certs/remoted.pem}"
        WAZUH_AUTHD_SSL_MANAGER_KEY="${WAZUH_REMOTE_HTTPS_KEY:-etc/certs/remoted-key.pem}"
        sed -e "s|\${INSTALLDIR}|$INSTALLDIR|g" \
            -e "s|\${WAZUH_AUTHD_SSL_MANAGER_CERT}|$WAZUH_AUTHD_SSL_MANAGER_CERT|g" \
            -e "s|\${WAZUH_AUTHD_SSL_MANAGER_KEY}|$WAZUH_AUTHD_SSL_MANAGER_KEY|g" \
            "${AUTH_TEMPLATE}" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
        DisableAuthd
    fi

    if command -v openssl >/dev/null 2>&1; then
        CLUSTER_KEY=$(openssl rand -hex 16)
    else
        CLUSTER_KEY=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    # Writting cluster configuration
    sed -e "s|\${CLUSTER_KEY}|$CLUSTER_KEY|g" "${CLUSTER_TEMPLATE}" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "</wazuh_config>" >> $NEWCONFIG

}

InstallCommon()
{
  WAZUH_GROUP='wazuh'
  WAZUH_USER='wazuh'
  INSTALL="install"

  if [ ${INSTYPE} = 'manager' ]; then
      WAZUH_GROUP='wazuh-manager'
      WAZUH_USER='wazuh-manager'
      WAZUH_CONTROL_SRC='./init/wazuh-server.sh'
      WAZUH_CONF_SRC='../etc/wazuh-manager.conf'
  elif [ ${INSTYPE} = 'agent' ]; then
      WAZUH_CONTROL_SRC='./init/wazuh-client.sh'
      WAZUH_CONF_SRC='../etc/ossec-agent.conf'
  fi

  if [ ${INSTYPE} = 'manager' ]; then
      WAZUH_CONF="wazuh-manager.conf"
      WAZUH_LOGFILE="wazuh-manager.log"
      WAZUH_LOGJSON="wazuh-manager.json"
  else
      WAZUH_CONF="ossec.conf"
      WAZUH_LOGFILE="ossec.log"
      WAZUH_LOGJSON="ossec.json"
  fi

  ./init/adduser.sh ${WAZUH_USER} ${WAZUH_GROUP} ${INSTALLDIR}

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/

  # Install VERSION.json and append commit id if any
  ${INSTALL} -m 440 -o root -g ${WAZUH_GROUP} ../VERSION.json ${INSTALLDIR}/VERSION.json

  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/wazuh
  ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/${WAZUH_LOGFILE}
  ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/${WAZUH_LOGJSON}

  if [ ${INSTYPE} = 'agent' ]; then
      ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/active-responses.log
  fi

    if [ ${INSTYPE} = 'agent' ]; then
        ${INSTALL} -d -m 0750 -o root -g 0 ${INSTALLDIR}/bin
    else
        ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/bin
    fi

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/lib

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libwazuhext.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libwazuhext.dylib ${INSTALLDIR}/lib
        fi
    elif [ -f build/lib/libwazuhext.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libwazuhext.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libwazuhext.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libdbsync.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libdbsync.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libdbsync.dylib ${INSTALLDIR}/lib/libdbsync.dylib
        fi
        if [ -f build/lib/libagent_sync_protocol.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib/libagent_sync_protocol.dylib
        fi
        if [ -f build/lib/libagent_metadata.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libagent_metadata.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libagent_metadata.dylib ${INSTALLDIR}/lib/libagent_metadata.dylib
        fi
        if [ -f build/lib/libhttps_client.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libhttps_client.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libhttps_client.dylib ${INSTALLDIR}/lib/libhttps_client.dylib
        fi
    elif [ -f build/lib/libdbsync.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libdbsync.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libdbsync.so
        fi
    fi
    if [ -f build/lib/libagent_sync_protocol.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libagent_sync_protocol.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libagent_sync_protocol.so
        fi
    fi
    if [ -f build/lib/libagent_metadata.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libagent_metadata.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libagent_metadata.so
        fi
    fi
    if [ -f build/lib/libhttps_client.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libhttps_client.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libhttps_client.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libschema_validator.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libschema_validator.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libschema_validator.dylib ${INSTALLDIR}/lib/libschema_validator.dylib
        fi
    elif [ -f build/lib/libschema_validator.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libschema_validator.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libschema_validator.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libsysinfo.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libsysinfo.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsysinfo.dylib ${INSTALLDIR}/lib/libsysinfo.dylib
        fi
    elif [ -f build/lib/libsysinfo.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libsysinfo.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsysinfo.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libfimdb.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libfimdb.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libfimdb.dylib ${INSTALLDIR}/lib/libfimdb.dylib
        fi
    elif [ -f build/lib/libfimdb.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libfimdb.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libfimdb.so
        fi
    fi

    if [ ${NUNAME} != 'Darwin' ]
    then
    	if [ -f build/lib/libfimebpf.so ]
    	then
       		${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libfimebpf.so ${INSTALLDIR}/lib

       		if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
       		    chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libfimebpf.so
       		fi
      fi

      if [ "X${INSTYPE}" = "Xagent" ]; then
          if [ -f external/libbpf-bootstrap/build/libbpf/libbpf.so ]
              then
                  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} external/libbpf-bootstrap/build/libbpf/libbpf.so ${INSTALLDIR}/lib

                  if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
                      chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libbpf.so
                  fi
          fi

          if [ -f external/libbpf-bootstrap/build/modern.bpf.o ]
              then
                  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} external/libbpf-bootstrap/build/modern.bpf.o ${INSTALLDIR}/lib

                  if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
                      chcon -t textrel_shlib_t ${INSTALLDIR}/lib/modern.bpf.o
                  fi
          fi
      fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libsyscollector.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libsyscollector.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsyscollector.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/build/lib/libsysinfo.dylib @rpath/../lib/libsysinfo.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/build/lib/libdbsync.dylib @rpath/../lib/libdbsync.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/build/lib/libagent_sync_protocol.dylib @rpath/../lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
        fi
    elif [ -f build/lib/libsyscollector.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libsyscollector.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsyscollector.so
        fi
    fi

    if [ -f build/lib/libinventory_sync_server.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libinventory_sync_server.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libinventory_sync_server.so
        fi
    fi

    if [ -f build/lib/libkeystore_server.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libkeystore_server.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libkeystore_server.so
        fi
    fi

    if [ -f build/lib/libvulnerability_scanner.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libvulnerability_scanner.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libvulnerability_scanner.so
        fi
    fi

    if [ -f build/lib/libremoted_module.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libremoted_module.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libremoted_module.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libsca.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libsca.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsca.dylib ${INSTALLDIR}/lib/libsca.dylib
        fi
    elif [ -f build/lib/libsca.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libsca.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsca.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f build/lib/libagent_info.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 build/lib/libagent_info.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libagent_info.dylib ${INSTALLDIR}/lib/libagent_info.dylib
        fi
    elif [ -f build/lib/libagent_info.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libagent_info.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libagent_info.so
        fi
    fi


    if [ -f build/lib/libstdc++.so.6 ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libstdc++.so.6 ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libstdc++.so.6
        fi
    fi

    if [ -f build/lib/libgcc_s.so.1 ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libgcc_s.so.1 ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libgcc_s.so.1
        fi
    fi

  if [ "X${INSTYPE}" = "Xagent" ]; then
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-logcollector ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-syscheckd ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-execd ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-modulesd ${INSTALLDIR}/bin/
  else
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-modulesd ${INSTALLDIR}/bin/
    ${INSTALL} -m 4750 -o root -g ${WAZUH_GROUP} build/bin/wazuh-manager-service-control ${INSTALLDIR}/bin/
  fi
  if [ "X${INSTYPE}" = "Xmanager" ]; then
    ${INSTALL} -m 0750 -o root -g 0 ${WAZUH_CONTROL_SRC} ${INSTALLDIR}/bin/wazuh-manager-control
  else
    ${INSTALL} -m 0750 -o root -g 0 ${WAZUH_CONTROL_SRC} ${INSTALLDIR}/bin/wazuh-control
  fi

  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue
  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sockets
  if [ "X${INSTYPE}" = "Xagent" ]; then
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/diff
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/agent_info
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/agent_info/db
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/fim
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/fim/db
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/syscollector
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/syscollector/db
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sca
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sca/db
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/logcollector
  fi

  if [ "X${INSTYPE}" = "Xagent" ]; then
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/ruleset
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/ruleset/sca
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/wodles
  fi

  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc

    if [ -f /etc/localtime ]
    then
         ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /etc/localtime ${INSTALLDIR}/etc
    fi

  ${INSTALL} -d -m 1770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/tmp

    if [ -f /etc/TIMEZONE ]; then
         ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /etc/TIMEZONE ${INSTALLDIR}/etc/
    fi

    if [ "X${INSTYPE}" = "Xagent" ]; then
        ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} -b ../etc/internal_options.conf ${INSTALLDIR}/etc/
        ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} wazuh_modules/syscollector/norm_config.json ${INSTALLDIR}/queue/syscollector
        if [ ! -f ${INSTALLDIR}/etc/local_internal_options.conf ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../etc/local_internal_options.conf ${INSTALLDIR}/etc/local_internal_options.conf
        fi
    else
        if [ ! -f ${INSTALLDIR}/etc/wazuh-manager-internal-options.conf ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../etc/wazuh-manager-internal-options.conf ${INSTALLDIR}/etc/wazuh-manager-internal-options.conf
        fi
    fi

    if [ ! -f ${INSTALLDIR}/etc/client.keys ]; then
        if [ "X${INSTYPE}" = "Xagent" ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        else
            ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        fi
    fi

    if [ ! -f ${INSTALLDIR}/etc/${WAZUH_CONF} ]; then
        if [ ! -f ../etc/wazuh.mc ]; then
            echo "WARNING: missing ../etc/wazuh.mc. Regenerating configuration template."
            if ! ./init/gen_wazuh.sh conf "${INSTYPE}" "${DIST_NAME}" "${DIST_VER}.${DIST_SUBVER}" "${INSTALLDIR}" > ../etc/wazuh.mc; then
                rm -f ../etc/wazuh.mc
                echo "WARNING: unable to regenerate ../etc/wazuh.mc."
            fi
        fi

        if [ -f ../etc/wazuh.mc ]; then
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ../etc/wazuh.mc ${INSTALLDIR}/etc/${WAZUH_CONF}
        else
            echo "WARNING: unable to generate ${WAZUH_CONF} with desired configurations, using default configurations from ${WAZUH_CONF_SRC}"
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ${WAZUH_CONF_SRC} ${INSTALLDIR}/etc/${WAZUH_CONF}
        fi
    fi


  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/shared
  if [ "X${INSTYPE}" = "Xagent" ]; then
    # Active response scripts and helpers are agent runtime assets.
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/active-response
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/active-response/bin
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/bin/block-ip ${INSTALLDIR}/active-response/bin/
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/bin/disable-account ${INSTALLDIR}/active-response/bin/
  fi

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/run
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/upgrade

  if [ "X${INSTYPE}" = "Xagent" ]; then
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/selinux
    if [ -f selinux/wazuh.pp ]; then
      ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} selinux/wazuh.pp ${INSTALLDIR}/var/selinux/
      InstallSELinuxPolicyPackage
    fi
  fi

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/backup

}


installIndexerTemplates()
{
    local SRC_DIR="external/indexer-plugins"
    local DEST_DIR="${INSTALLDIR}/etc/indexer-plugins"
    local STREAMS="metrics-agents.json metrics-comms.json metrics-normalization.json"

    if [ ! -d "${SRC_DIR}" ]; then
        echo "WARNING: ${SRC_DIR} not found. Metrics schemas will be missing."
        return 0
    fi

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} "${DEST_DIR}"
    for f in ${STREAMS}; do
        if [ -f "${SRC_DIR}/${f}" ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} "${SRC_DIR}/${f}" "${DEST_DIR}/"
        else
            echo "WARNING: ${SRC_DIR}/${f} not found."
        fi
    done
}

generateSchemaFiles()
{
    echo "Generating schema files..."
    ${INSTALLDIR}/framework/python/bin/python3 engine/tools/engine-schema/engine_schema.py generate \
    --output-dir engine/ruleset/schemas/ \
    --wcs-path external/wcs-flat-files/ \
    --decoder-template engine/ruleset/schemas/wazuh-decoders.template.json \
    --exclude-geo engine/ruleset/schemas/exclude-enrichment-geo.json \
    --ioc-enrichment-cfg engine/ruleset/schemas/ioc-enrichment-cfg.json

    if [ $? != 0 ]; then
        echo "Error: Failed to generate schema files."
        exit 1
    fi
    echo "Schema files generated successfully."
}

installEngineStore()
{
    local DEST_FULL_PATH=${INSTALLDIR}/data
    local ENGINE_SRC_PATH=./engine

    # Fallback store installation
    local STORE_PATH=${DEST_FULL_PATH}/store
    local SCHEMA_PATH=${STORE_PATH}/schema
    local ENRICHMENT_PATH=${STORE_PATH}/enrichment
    local ENGINE_SCHEMA_PATH=${SCHEMA_PATH}/engine-schema/
    local ENGINE_LOGPAR_TYPE_PATH=${SCHEMA_PATH}/wazuh-logpar-overrides
    local ENGINE_ALLOWED_FIELDS_PATH=${SCHEMA_PATH}/allowed-fields
    local ENGINE_ENRICHMENT_GEO=${ENRICHMENT_PATH}/geo
    local ENGINE_ENRICHMENT_IOC=${ENRICHMENT_PATH}/ioc

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${STORE_PATH}
    mkdir -p "${ENGINE_SCHEMA_PATH}"
    mkdir -p "${ENGINE_LOGPAR_TYPE_PATH}"
    mkdir -p "${ENGINE_ALLOWED_FIELDS_PATH}"
    mkdir -p "${ENGINE_ENRICHMENT_GEO}"
    mkdir -p "${ENGINE_ENRICHMENT_IOC}"

    # Copying the store files
    echo "Copying store files..."
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/engine-schema.json" "${ENGINE_SCHEMA_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/wazuh-logpar-overrides.json" "${ENGINE_LOGPAR_TYPE_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/allowed-fields.json" "${ENGINE_ALLOWED_FIELDS_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/enrichment-geo.json" "${ENGINE_ENRICHMENT_GEO}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/enrichment-ioc.json" "${ENGINE_ENRICHMENT_IOC}/0"

    if [ ! -f "${ENGINE_SCHEMA_PATH}/0" ] || [ ! -f "${ENGINE_LOGPAR_TYPE_PATH}/0" ] \
        || [ ! -f "${ENGINE_ALLOWED_FIELDS_PATH}/0" ] || [ ! -f "${ENGINE_ENRICHMENT_GEO}/0" ] \
        || [ ! -f "${ENGINE_ENRICHMENT_IOC}/0" ]; then
        echo "Error: Failed to copy store files."
        exit 1
    fi

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${STORE_PATH}
    find ${STORE_PATH} -type d -exec chmod 770 {} \; -o -type f -exec chmod 660 {} \;

    echo "Engine store installed successfully."

    # Copy default output configuration files
    local OUTPUTS_PATH=${INSTALLDIR}/etc/outputs
    local DEFAULT_OUTPUTS_PATH=${OUTPUTS_PATH}/default
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${DEFAULT_OUTPUTS_PATH}
    cp "${ENGINE_SRC_PATH}/ruleset/outputs/"*.yml "${DEFAULT_OUTPUTS_PATH}/"
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${OUTPUTS_PATH}
    find ${OUTPUTS_PATH} -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;

    # Create /var/wazuh-manager/data/ruleset
    # Owned by ${WAZUH_USER}: the engine drops root privileges at startup and
    # the CM store verifies write access to this directory.
    install -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/data/ruleset
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${INSTALLDIR}/data/ruleset

    echo "Engine output configuration files installed successfully."
}

installGeoIP()
{
    DEST_FULL_PATH=${INSTALLDIR}/data
    GEOIP_SRC_PATH=./external/geo_db

    local MMDB_PATH=${DEST_FULL_PATH}/mmdb
    local STORE_GEO_PATH=${DEST_FULL_PATH}/store/geo/mmdb
    local MANIFEST_FILE=${GEOIP_SRC_PATH}/manifest.json

    # Create directories
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${MMDB_PATH}
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${DEST_FULL_PATH}/store/geo
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${STORE_GEO_PATH}

    # Check if GeoIP files exist
    if [ ! -f "${GEOIP_SRC_PATH}/GeoLite2-ASN.mmdb" ] || [ ! -f "${GEOIP_SRC_PATH}/GeoLite2-City.mmdb" ]; then
        echo "Warning: GeoIP database files not found in ${GEOIP_SRC_PATH}. Skipping GeoIP installation."
        return 0
    fi

    if [ ! -f "${MANIFEST_FILE}" ]; then
        echo "Warning: GeoIP manifest.json not found. Skipping GeoIP installation."
        return 0
    fi

    echo "Installing GeoIP databases..."

    # Copy .mmdb files
    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} "${GEOIP_SRC_PATH}/GeoLite2-ASN.mmdb" "${MMDB_PATH}/"
    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} "${GEOIP_SRC_PATH}/GeoLite2-City.mmdb" "${MMDB_PATH}/"

    # Parse manifest.json without jq or python - using grep and sed
    ASN_MD5=$(grep -A 2 '"asn"' "${MANIFEST_FILE}" | grep '"md5"' | sed 's/.*"md5"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    CITY_MD5=$(grep -A 2 '"city"' "${MANIFEST_FILE}" | grep '"md5"' | sed 's/.*"md5"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    GENERATED_AT=$(grep '"generated_at"' "${MANIFEST_FILE}" | sed 's/.*"generated_at"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/')

    # Generate metadata JSON file
    cat > "${STORE_GEO_PATH}/0" << EOF
{
    "city": {
        "path": "${MMDB_PATH}/GeoLite2-City.mmdb",
        "hash": "${CITY_MD5}",
        "generated_at": ${GENERATED_AT}
    },
    "asn": {
        "path": "${MMDB_PATH}/GeoLite2-ASN.mmdb",
        "hash": "${ASN_MD5}",
        "generated_at": ${GENERATED_AT}
    }
}
EOF

    # Set proper ownership and permissions
    chown ${WAZUH_USER}:${WAZUH_GROUP} "${STORE_GEO_PATH}/0"
    chmod 660 "${STORE_GEO_PATH}/0"

    echo "GeoIP databases installed successfully."
}

installTZDB()
{
    local TZDB_SRC_PATH=./external/tzdata
    local TZDB_DST_PATH=${INSTALLDIR}/data/tzdb/iana

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/data/tzdb
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${TZDB_DST_PATH}

    if [ ! -f "${TZDB_SRC_PATH}/version" ]; then
        echo "Warning: Timezone database not found in ${TZDB_SRC_PATH}. Skipping TZDB installation."
        return 0
    fi

    echo "Installing timezone database..."

    cp -r "${TZDB_SRC_PATH}/." "${TZDB_DST_PATH}/"
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} "${TZDB_DST_PATH}"
    find "${TZDB_DST_PATH}" -type f -exec chmod 0640 {} +
    find "${TZDB_DST_PATH}" -type d -exec chmod 0750 {} +

    echo "Timezone database installed successfully."
}

InstallLocal()
{

    InstallCommon

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/var/multigroups
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/db
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/download
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/api

    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-monitord ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/bin/verify-agent-conf ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-db ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 build/engine/wazuh-engine ${INSTALLDIR}/bin/wazuh-manager-analysisd

    ### Install Python
    ${MAKEBIN} wpython INSTALLDIR=${INSTALLDIR} TARGET=${INSTYPE}

    ${MAKEBIN} --quiet -C ../framework install INSTALLDIR=${INSTALLDIR} WAZUH_GROUP=${WAZUH_GROUP}
    # Framework installation may leave this parent directory with default root:root 755.
    # Keep it aligned with the manager baseline used by check_files.
    if [ -d "${INSTALLDIR}/framework/wazuh/core" ]; then
        chown root:${WAZUH_GROUP} "${INSTALLDIR}/framework/wazuh/core"
        chmod 0750 "${INSTALLDIR}/framework/wazuh/core"
    fi

    generateSchemaFiles

    installIndexerTemplates

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/data

    installEngineStore

    installGeoIP

    installTZDB

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/data/kvdb-ioc
    # Contents created by root in previous versions must remain writable after
    # the engine drops privileges (RocksDB requires owner write access).
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${INSTALLDIR}/data/kvdb-ioc
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/db

    # Engine streamlog trees (logs/<YYYY>/...) created by root in previous
    # versions must remain writable after the engine drops privileges. Scoped
    # to year-pattern directories so other daemons' files are untouched.
    for YEAR_DIR in ${INSTALLDIR}/logs/[0-9][0-9][0-9][0-9]; do
        if [ -d "${YEAR_DIR}" ]; then
            chown -R ${WAZUH_USER}:${WAZUH_GROUP} "${YEAR_DIR}"
        fi
    done

    if [ "X${OPTIMIZE_CPYTHON}" = "Xy" ]; then
        CPYTHON_FLAGS="OPTIMIZE_CPYTHON=yes"
    fi

    # Install Vulnerability Detector files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/vd
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/indexer


    # Install Task Manager files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/tasks

    ### Backup old API
    if [ "X${update_only}" = "Xyes" ]; then
      ${MAKEBIN} --quiet -C ../api backup INSTALLDIR=${INSTALLDIR} WAZUH_GROUP=${WAZUH_GROUP}
    fi

    ### Install API
    ${MAKEBIN} --quiet -C ../api install INSTALLDIR=${INSTALLDIR} WAZUH_GROUP=${WAZUH_GROUP}

    ### Restore old API
    if [ "X${update_only}" = "Xyes" ]; then
      ${MAKEBIN} --quiet -C ../api restore INSTALLDIR=${INSTALLDIR} WAZUH_GROUP=${WAZUH_GROUP}
    fi
}

TransferShared()
{
    rm -f ${INSTALLDIR}/etc/shared/merged.mg
    find ${INSTALLDIR}/etc/shared -maxdepth 1 -type f -exec mv -f {} ${INSTALLDIR}/etc/shared/default \;
}

InstallServer()
{

    InstallLocal
    if [ -f build/lib/libwazuhshared.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libwazuhshared.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libwazuhshared.so
        fi
    fi
    if [ -f external/jemalloc/lib/libjemalloc.so.2 ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} external/jemalloc/lib/libjemalloc.so.2 ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libjemalloc.so.2
        fi
    fi
    if [ -f build/lib/libcontent_manager.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libcontent_manager.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libcontent_manager.so
        fi
    fi

    if [ -f build/lib/libindexer_connector.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/lib/libindexer_connector.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libindexer_connector.so
        fi
    fi
    if [ -f external/rocksdb/build/librocksdb.so.8 ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} external/rocksdb/build/librocksdb.so.8 ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/librocksdb.so.8
        fi
    fi

    # Install cluster files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/cluster
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/cluster

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/shared/default

    TransferShared

    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-remoted ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-authd ${INSTALLDIR}/bin

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/rids

    if [ ! -f ${INSTALLDIR}/queue/agents-timestamp ]; then
        ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/queue/agents-timestamp
    fi

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/backup/db

    if [ ! -f ${INSTALLDIR}/etc/shared/default/agent.conf ]; then
        ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../etc/agent.conf ${INSTALLDIR}/etc/shared/default
    fi

    if [ ! -f ${INSTALLDIR}/etc/shared/agent-template.conf ]; then
        ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../etc/agent.conf ${INSTALLDIR}/etc/shared/agent-template.conf
    fi

    GenerateHttpsManagerCert
    SetIndexerCertsOwnership

    # authd's durable state: the agent deletions whose indexer purge is still pending
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/authd

    # Keystore
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/keystore
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-manager-keystore ${INSTALLDIR}/bin/wazuh-manager-keystore
}

InstallAgent()
{

    InstallCommon

    InstallSecurityConfigurationAssessmentFiles "agent"

    ${INSTALL} -m 0750 -o root -g 0 build/bin/manage_agents ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 build/bin/wazuh-agentd ${INSTALLDIR}/bin

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/rids
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/incoming
    ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../etc/wpk_root.pem ${INSTALLDIR}/etc/

    # Install the plugins files
    # Don't install the plugins if they are already installed.
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/__init__.py ${INSTALLDIR}/wodles/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/utils.py ${INSTALLDIR}/wodles/utils.py

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/buckets_s3
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/services
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/subscribers
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/aws_s3.py ${INSTALLDIR}/wodles/aws/aws-s3
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/__init__.py ${INSTALLDIR}/wodles/aws/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/aws_tools.py ${INSTALLDIR}/wodles/aws/aws_tools.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/wazuh_integration.py ${INSTALLDIR}/wodles/aws/wazuh_integration.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/aws_bucket.py ${INSTALLDIR}/wodles/aws/buckets_s3/aws_bucket.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/cloudtrail.py ${INSTALLDIR}/wodles/aws/buckets_s3/cloudtrail.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/config.py ${INSTALLDIR}/wodles/aws/buckets_s3/config.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/guardduty.py ${INSTALLDIR}/wodles/aws/buckets_s3/guardduty.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/__init__.py ${INSTALLDIR}/wodles/aws/buckets_s3/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/load_balancers.py ${INSTALLDIR}/wodles/aws/buckets_s3/load_balancers.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/server_access.py ${INSTALLDIR}/wodles/aws/buckets_s3/server_access.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/umbrella.py ${INSTALLDIR}/wodles/aws/buckets_s3/umbrella.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/vpcflow.py ${INSTALLDIR}/wodles/aws/buckets_s3/vpcflow.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/buckets_s3/waf.py ${INSTALLDIR}/wodles/aws/buckets_s3/waf.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/services/aws_service.py ${INSTALLDIR}/wodles/aws/services/aws_service.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/services/cloudwatchlogs.py ${INSTALLDIR}/wodles/aws/services/cloudwatchlogs.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/services/__init__.py ${INSTALLDIR}/wodles/aws/services/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/services/inspector.py ${INSTALLDIR}/wodles/aws/services/inspector.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/subscribers/__init__.py ${INSTALLDIR}/wodles/aws/subscribers/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/subscribers/sqs_queue.py ${INSTALLDIR}/wodles/aws/subscribers/sqs_queue.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/subscribers/s3_log_handler.py ${INSTALLDIR}/wodles/aws/subscribers/s3_log_handler.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/subscribers/sqs_message_processor.py ${INSTALLDIR}/wodles/aws/subscribers/sqs_message_processor.py

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud/pubsub
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud/buckets
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/gcloud.py ${INSTALLDIR}/wodles/gcloud/gcloud
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/integration.py ${INSTALLDIR}/wodles/gcloud/integration.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/tools.py ${INSTALLDIR}/wodles/gcloud/tools.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/exceptions.py ${INSTALLDIR}/wodles/gcloud/exceptions.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/buckets/bucket.py ${INSTALLDIR}/wodles/gcloud/buckets/bucket.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/buckets/access_logs.py ${INSTALLDIR}/wodles/gcloud/buckets/access_logs.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/pubsub/subscriber.py ${INSTALLDIR}/wodles/gcloud/pubsub/subscriber.py

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/docker
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/docker-listener/DockerListener.py ${INSTALLDIR}/wodles/docker/DockerListener

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure/azure_services
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure/db
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure-logs.py ${INSTALLDIR}/wodles/azure/azure-logs
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_utils.py ${INSTALLDIR}/wodles/azure/azure_utils.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/__init__.py ${INSTALLDIR}/wodles/azure/azure_services/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/analytics.py ${INSTALLDIR}/wodles/azure/azure_services/analytics.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/graph.py ${INSTALLDIR}/wodles/azure/azure_services/graph.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/storage.py ${INSTALLDIR}/wodles/azure/azure_services/storage.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/__init__.py ${INSTALLDIR}/wodles/azure/db/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/orm.py ${INSTALLDIR}/wodles/azure/db/orm.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/utils.py ${INSTALLDIR}/wodles/azure/db/utils.py
}

InstallWazuh()
{
    if [ "X$INSTYPE" = "Xagent" ]; then
        InstallAgent
    elif [ "X$INSTYPE" = "Xmanager" ]; then
        InstallServer
    fi
}
