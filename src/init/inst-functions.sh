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
GLOBAL_AR_TEMPLATE="./etc/templates/config/generic/global-ar.template"
AR_COMMANDS_TEMPLATE="./etc/templates/config/generic/ar-commands.template"
AR_DEFINITIONS_TEMPLATE="./etc/templates/config/generic/ar-definitions.template"
LOGGING_TEMPLATE="./etc/templates/config/generic/logging.template"
REMOTE_SEC_TEMPLATE="./etc/templates/config/generic/remote-secure.template"

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
        echo "    <!-- Generate alert when new file detected -->" >> $NEWCONFIG
        echo "    <alert_new_files>yes</alert_new_files>" >> $NEWCONFIG
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
    echo "  <!-- Configuration for wazuh-authd -->" >> $NEWCONFIG
    echo "  <auth>" >> $NEWCONFIG
    echo "    <disabled>yes</disabled>" >> $NEWCONFIG
    echo "    <port>1515</port>" >> $NEWCONFIG
    echo "    <use_source_ip>no</use_source_ip>" >> $NEWCONFIG
    echo "    <purge>yes</purge>" >> $NEWCONFIG
    echo "    <use_password>no</use_password>" >> $NEWCONFIG
    echo "    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>" >> $NEWCONFIG
    echo "    <!-- <ssl_agent_ca></ssl_agent_ca> -->" >> $NEWCONFIG
    echo "    <ssl_verify_host>no</ssl_verify_host>" >> $NEWCONFIG
    echo "    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>" >> $NEWCONFIG
    echo "    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>" >> $NEWCONFIG
    echo "    <ssl_auto_negotiate>no</ssl_auto_negotiate>" >> $NEWCONFIG
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

    if [ "X$1" = "Xmanager" ]; then
        CONFIGURATION_ASSESSMENT_MANAGER_FILES_PATH=$(GetTemplate "sca.$1.files" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
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

    if [ "X$1" = "Xmanager" ]; then
        echo "Installing additional SCA policies..."
        CONFIGURATION_ASSESSMENT_FILES=$(cat .$CONFIGURATION_ASSESSMENT_MANAGER_FILES_PATH)
        for FILE in $CONFIGURATION_ASSESSMENT_FILES; do
            FILENAME=$(basename $FILE)
            if [ -f "../ruleset/sca/$FILE" ] && [ ! -f "${INSTALLDIR}/ruleset/sca/$FILENAME" ]; then
                ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../ruleset/sca/$FILE ${INSTALLDIR}/ruleset/sca/
                mv ${INSTALLDIR}/ruleset/sca/$FILENAME ${INSTALLDIR}/ruleset/sca/$FILENAME.disabled
            fi
        done
    fi
}

##########
# GenerateAuthCert()
##########
GenerateAuthCert()
{
    if [ "X$SSL_CERT" = "Xyes" ]; then
        # Generation auto-signed certificate if not exists
        if [ ! -f "${INSTALLDIR}/etc/sslmanager.key" ] && [ ! -f "${INSTALLDIR}/etc/sslmanager.cert" ]; then
            if [ ! "X${USER_GENERATE_AUTHD_CERT}" = "Xn" ]; then
                    echo "Generating self-signed certificate for wazuh-authd..."
                    ${INSTALLDIR}/bin/wazuh-authd -C 365 -B 2048 -K ${INSTALLDIR}/etc/sslmanager.key -X ${INSTALLDIR}/etc/sslmanager.cert -S "/C=US/ST=California/CN=wazuh/"
                    chmod 640 ${INSTALLDIR}/etc/sslmanager.key
                    chmod 640 ${INSTALLDIR}/etc/sslmanager.cert
            fi
        fi
    fi
}

##########
# WriteLogs()
##########
WriteLogs()
{
  LOCALFILES_TMP=`cat ${LOCALFILES_TEMPLATE}`
  HAS_JOURNALD=`command -v journalctl`

  # If has journald, add journald to the configuration file
  if [ "X$HAS_JOURNALD" != "X" ]; then
    if [ "$1" = "echo" ]; then
      echo "    -- journald"
    elif [ "$1" = "add" ]; then
      echo "  <localfile>" >> $NEWCONFIG
      echo "    <log_format>journald</log_format>" >> $NEWCONFIG
      echo "    <location>journald</location>" >> $NEWCONFIG
      echo "  </localfile>" >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
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
        if [ "$1" = "echo" ]; then
            echo "    -- $FILE"
        # Add to the configuration file
        elif [ "$1" = "add" ]; then
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
# SetHeaders() 1-agent|manager|local
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
    sed "s|WAZUH_HOME_TMP|${INSTALLDIR}|g" ${SERVICE_TEMPLATE}
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
    echo "  <client>" >> $NEWCONFIG
    echo "    <server>" >> $NEWCONFIG
    if [ "X${HNAME}" = "X" ]; then
      echo "      <address>$SERVER_IP</address>" >> $NEWCONFIG
    else
      echo "      <address>$HNAME</address>" >> $NEWCONFIG
    fi
    echo "      <port>1514</port>" >> $NEWCONFIG
    echo "    </server>" >> $NEWCONFIG
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
    echo "    <notify_time>20</notify_time>" >> $NEWCONFIG
    echo "    <time-reconnect>60</time-reconnect>" >> $NEWCONFIG
    echo "    <auto_restart>yes</auto_restart>" >> $NEWCONFIG
    echo "  </client>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "  <client_buffer>" >> $NEWCONFIG
    echo "    <!-- Agent buffer options -->" >> $NEWCONFIG
    echo "    <disabled>no</disabled>" >> $NEWCONFIG
    echo "    <queue_size>5000</queue_size>" >> $NEWCONFIG
    echo "    <events_per_second>500</events_per_second>" >> $NEWCONFIG
    echo "  </client_buffer>" >> $NEWCONFIG
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
# WriteManager() $1="no_locafiles" or empty
##########
WriteManager()
{
    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Manager")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<ossec_config>" >> $NEWCONFIG

    GLOBAL_CONTENT=$(cat ${GLOBAL_TEMPLATE})

    if [ "$UPDATE_CHECK" = "no" ]; then
        GLOBAL_CONTENT=$(echo "$GLOBAL_CONTENT" | sed "s|<update_check>yes</update_check>|<update_check>no</update_check>|g")
    fi

    echo "$GLOBAL_CONTENT" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Remote connection secure
    if [ "X$SLOG" = "Xyes" ]; then
      cat ${REMOTE_SEC_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    # Write rootcheck
    WriteRootcheck "manager"

    # Syscollector configuration
    WriteSyscollector "manager"

    # Configuration assessment
    WriteConfigurationAssessment

    # Vulnerability Detector
    cat ${VULN_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Indexer
    cat ${INDEXER_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write syscheck
    WriteSyscheck "manager"

    # Active response
    if [ "$SET_WHITE_LIST"="true" ]; then
       sed -e "/  <\/global>/d" "${GLOBAL_AR_TEMPLATE}" >> $NEWCONFIG
      # Nameservers in /etc/resolv.conf
      for ip in ${NAMESERVERS} ${NAMESERVERS2};
        do
          if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
          fi
      done
      # Read string
      for ip in ${IPS};
        do
          if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
            echo $ip | grep -E "^[0-9./]{5,20}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
            fi
          fi
        done
        echo "  </global>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
      cat ${GLOBAL_AR_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    cat ${AR_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG
    cat ${AR_DEFINITIONS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write the log files
    if [ "X${NO_LOCALFILES}" = "X" ]; then
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
      WriteLogs "add"
    else
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
    fi

    # Localfile commands
    LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_COMMANDS_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cat ${LOCALFILE_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Localfile extra
    LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    if [ ! "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      cat ${LOCALFILE_EXTRA_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi


    # Writting auth configuration
    if [ "X${AUTHD}" = "Xyes" ]; then
        sed -e "s|\${INSTALLDIR}|$INSTALLDIR|g" "${AUTH_TEMPLATE}" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
        DisableAuthd
    fi

    # Writting cluster configuration
    cat ${CLUSTER_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "</ossec_config>" >> $NEWCONFIG

}

##########
# WriteLocal() $1="no_locafiles" or empty
##########
WriteLocal()
{
    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Local")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<ossec_config>" >> $NEWCONFIG
    cat ${GLOBAL_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write rootcheck
    WriteRootcheck "manager"

    # Vulnerability Detector
    cat ${VULN_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Indexer
    cat ${INDEXER_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write syscheck
    WriteSyscheck "manager"

    # Active response
    if [ "$SET_WHITE_LIST"="true" ]; then
       sed -e "/  <\/global>/d" "${GLOBAL_AR_TEMPLATE}" >> $NEWCONFIG
      # Nameservers in /etc/resolv.conf
      for ip in ${NAMESERVERS} ${NAMESERVERS2};
        do
          if [ ! "X${ip}" = "X" ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
          fi
      done
      # Read string
      for ip in ${IPS};
        do
          if [ ! "X${ip}" = "X" ]; then
            echo $ip | grep -E "^[0-9./]{5,20}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
            fi
          fi
        done
        echo "  </global>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
      cat ${GLOBAL_AR_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    cat ${AR_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG
    cat ${AR_DEFINITIONS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write the log files
    if [ "X${NO_LOCALFILES}" = "X" ]; then
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
      WriteLogs "add"
    else
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
    fi

    # Localfile commands
    LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_COMMANDS_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cat ${LOCALFILE_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Localfile extra
    LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    if [ ! "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      cat ${LOCALFILE_EXTRA_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    echo "</ossec_config>" >> $NEWCONFIG
}

InstallCommon()
{

    WAZUH_GROUP='wazuh'
    WAZUH_USER='wazuh'
    INSTALL="install"

    if [ ${INSTYPE} = 'server' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-server.sh'
        OSSEC_CONF_SRC='../etc/ossec-server.conf'
    elif [ ${INSTYPE} = 'agent' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-client.sh'
        OSSEC_CONF_SRC='../etc/ossec-agent.conf'
    elif [ ${INSTYPE} = 'local' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-local.sh'
        OSSEC_CONF_SRC='../etc/ossec-local.conf'
    fi

    if [ ${DIST_NAME} = "sunos" ]; then
        INSTALL="ginstall"
    elif [ ${DIST_NAME} = "HP-UX" ]; then
        INSTALL="/usr/local/coreutils/bin/install"
   elif [ ${DIST_NAME} = "AIX" ]; then
        INSTALL="/opt/freeware/bin/install"
    fi

    ./init/adduser.sh ${WAZUH_USER} ${WAZUH_GROUP} ${INSTALLDIR}

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/

  # Install VERSION.json and append commit id if any
  ${INSTALL} -m 440 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../VERSION.json ${INSTALLDIR}/VERSION.json

  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/wazuh
  ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/ossec.log
  ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/ossec.json
  ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/logs/active-responses.log

    if [ ${INSTYPE} = 'agent' ]; then
        ${INSTALL} -d -m 0750 -o root -g 0 ${INSTALLDIR}/bin
    else
        ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/bin
    fi

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/lib

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f libwazuhext.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 libwazuhext.dylib ${INSTALLDIR}/lib
        fi
    elif [ -f libwazuhext.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libwazuhext.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libwazuhext.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f libwazuhshared.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 libwazuhshared.dylib ${INSTALLDIR}/lib
        fi
    elif [ -f libwazuhshared.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libwazuhshared.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libwazuhshared.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f shared_modules/dbsync/build/lib/libdbsync.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 shared_modules/dbsync/build/lib/libdbsync.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libdbsync.dylib ${INSTALLDIR}/lib/libdbsync.dylib
        fi
        if [ -f shared_modules/sync_protocol/build/lib/libagent_sync_protocol.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 shared_modules/sync_protocol/build/lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib/libagent_sync_protocol.dylib
        fi
    elif [ -f shared_modules/dbsync/build/lib/libdbsync.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} shared_modules/dbsync/build/lib/libdbsync.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libdbsync.so
        fi
    fi
    if [ -f shared_modules/sync_protocol/build/lib/libagent_sync_protocol.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} shared_modules/sync_protocol/build/lib/libagent_sync_protocol.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libagent_sync_protocol.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f data_provider/build/lib/libsysinfo.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 data_provider/build/lib/libsysinfo.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsysinfo.dylib ${INSTALLDIR}/lib/libsysinfo.dylib
        fi
    elif [ -f data_provider/build/lib/libsysinfo.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} data_provider/build/lib/libsysinfo.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsysinfo.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f syscheckd/build/lib/libfimdb.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 syscheckd/build/lib/libfimdb.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libfimdb.dylib ${INSTALLDIR}/lib/libfimdb.dylib
        fi
    elif [ -f syscheckd/build/lib/libfimdb.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} syscheckd/build/lib/libfimdb.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libfimdb.so
        fi
    fi

    if [ ${NUNAME} != 'Darwin' ]
    then
    	if [ -f syscheckd/build/lib/libfimebpf.so ]
    	then
       		${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} syscheckd/build/lib/libfimebpf.so ${INSTALLDIR}/lib

       		if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
       		    chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libfimebpf.so
       		fi
      fi

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

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f wazuh_modules/syscollector/build/lib/libsyscollector.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 wazuh_modules/syscollector/build/lib/libsyscollector.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsyscollector.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/data_provider/build/lib/libsysinfo.dylib @rpath/../lib/libsysinfo.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/shared_modules/dbsync/build/lib/libdbsync.dylib @rpath/../lib/libdbsync.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
            install_name_tool -change $(PWD)/shared_modules/sync_protocol/build/lib/libagent_sync_protocol.dylib @rpath/../lib/libagent_sync_protocol.dylib ${INSTALLDIR}/lib/libsyscollector.dylib
        fi
    elif [ -f wazuh_modules/syscollector/build/lib/libsyscollector.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} wazuh_modules/syscollector/build/lib/libsyscollector.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsyscollector.so
        fi
    fi

    if [ -f build/wazuh_modules/inventory_sync/libinventory_sync.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/wazuh_modules/inventory_sync/libinventory_sync.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libinventory_sync.so
        fi
    fi

    if [ ${NUNAME} = 'Darwin' ]
    then
        if [ -f wazuh_modules/sca/build/lib/libsca.dylib ]
        then
            ${INSTALL} -m 0750 -o root -g 0 wazuh_modules/sca/build/lib/libsca.dylib ${INSTALLDIR}/lib
            install_name_tool -id @rpath/../lib/libsca.dylib ${INSTALLDIR}/lib/libsca.dylib
        fi
    elif [ -f wazuh_modules/sca/build/lib/libsca.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} wazuh_modules/sca/build/lib/libsca.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libsca.so
        fi
    fi

    if [ ${DIST_NAME} = 'AIX' ]
    then
        if [ -f libstdc++.a ]
        then
            ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libstdc++.a ${INSTALLDIR}/lib
        fi

        if [ -f libgcc_s.a ]
        then
            ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libgcc_s.a ${INSTALLDIR}/lib
        fi
    else
        if [ -f libstdc++.so.6 ]
        then
            ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libstdc++.so.6 ${INSTALLDIR}/lib

            if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
                chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libstdc++.so.6
            fi
        fi

        if [ -f libgcc_s.so.1 ]
        then
            ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} libgcc_s.so.1 ${INSTALLDIR}/lib

            if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]) && [ ${DIST_VER} -le 5 ]; then
                chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libgcc_s.so.1
            fi
        fi
    fi

  ${INSTALL} -m 0750 -o root -g 0 wazuh-logcollector ${INSTALLDIR}/bin
  ${INSTALL} -m 0750 -o root -g 0 syscheckd/build/bin/wazuh-syscheckd ${INSTALLDIR}/bin
  ${INSTALL} -m 0750 -o root -g 0 wazuh-execd ${INSTALLDIR}/bin
  ${INSTALL} -m 0750 -o root -g 0 ${OSSEC_CONTROL_SRC} ${INSTALLDIR}/bin/wazuh-control
  ${INSTALL} -m 0750 -o root -g 0 wazuh-modulesd ${INSTALLDIR}/bin/

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/queue
  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/alerts
  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sockets
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/diff
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/fim
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/fim/db
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/syscollector
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/syscollector/db
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sca
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/sca/db
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/logcollector

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/ruleset
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/ruleset/sca

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/wodles

  ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/etc

    if [ -f /etc/localtime ]
    then
         ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /etc/localtime ${INSTALLDIR}/etc
    fi

  ${INSTALL} -d -m 1770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/tmp

    if [ -f /etc/TIMEZONE ]; then
         ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /etc/TIMEZONE ${INSTALLDIR}/etc/
    fi
    # Solaris Needs some extra files
    if [ ${DIST_NAME} = "SunOS" ]; then
      ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/usr/share/lib/zoneinfo/
        cp -rf /usr/share/lib/zoneinfo/* ${INSTALLDIR}/usr/share/lib/zoneinfo/
        chown root:${WAZUH_GROUP} ${INSTALLDIR}/usr/share/lib/zoneinfo/*
        find ${INSTALLDIR}/usr/share/lib/zoneinfo/ -type d -exec chmod 0750 {} +
        find ${INSTALLDIR}/usr/share/lib/zoneinfo/ -type f -exec chmod 0640 {} +
    fi

    ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} -b ../etc/internal_options.conf ${INSTALLDIR}/etc/
    ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} wazuh_modules/syscollector/norm_config.json ${INSTALLDIR}/queue/syscollector

    if [ ! -f ${INSTALLDIR}/etc/local_internal_options.conf ]; then
        ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../etc/local_internal_options.conf ${INSTALLDIR}/etc/local_internal_options.conf
    fi

    if [ ! -f ${INSTALLDIR}/etc/client.keys ]; then
        if [ ${INSTYPE} = 'agent' ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        else
            ${INSTALL} -m 0640 -o wazuh -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        fi
    fi

    if [ ! -f ${INSTALLDIR}/etc/ossec.conf ]; then
        if [ -f  ../etc/ossec.mc ]; then
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ../etc/ossec.mc ${INSTALLDIR}/etc/ossec.conf
        else
            echo "WARNING: unable to generate ossec.conf file with desired configurations, using default configurations from ${OSSEC_CONF_SRC}"
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ${OSSEC_CONF_SRC} ${INSTALLDIR}/etc/ossec.conf
        fi
    fi

  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/shared
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/active-response
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/active-response/bin
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/ruleset/assets
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/ruleset/kvdb

  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/.ssh

  ./init/fw-check.sh execute
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} active-response/*.sh ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} active-response/*.py ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} firewall-drop ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} default-firewall-drop ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} pf ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} npf ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ipfw ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} firewalld-drop ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} disable-account ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} host-deny ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ip-customblock ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} restart-wazuh ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} route-null ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} kaspersky ${INSTALLDIR}/active-response/bin/
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} wazuh-slack ${INSTALLDIR}/active-response/bin/

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/run
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/upgrade
  ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/selinux

  if [ -f selinux/wazuh.pp ]
  then
    ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} selinux/wazuh.pp ${INSTALLDIR}/var/selinux/
    InstallSELinuxPolicyPackage
  fi

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/backup

}


installEngineStore()
{
    DEST_FULL_PATH=${INSTALLDIR}/engine
    ENGINE_SRC_PATH=./engine

    # TODO: Get from content delivery, and if not available, use local store

    # Fallback store installation
    local STORE_PATH=${DEST_FULL_PATH}/store
    local KVDB_PATH=${DEST_FULL_PATH}/kvdb
    local SCHEMA_PATH=${STORE_PATH}/schema
    local ENGINE_SCHEMA_PATH=${SCHEMA_PATH}/engine-schema/
    local ENGINE_LOGPAR_TYPE_PATH=${SCHEMA_PATH}/wazuh-logpar-overrides
    local ENGINE_ALLOWED_FIELDS_PATH=${SCHEMA_PATH}/allowed-fields

    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${STORE_PATH}
    mkdir -p "${KVDB_PATH}"
    mkdir -p "${ENGINE_SCHEMA_PATH}"
    mkdir -p "${ENGINE_LOGPAR_TYPE_PATH}"
    mkdir -p "${ENGINE_ALLOWED_FIELDS_PATH}"

    # Copying the store files
    echo "Copying store files..."
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/engine-schema.json" "${ENGINE_SCHEMA_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/wazuh-logpar-overrides.json" "${ENGINE_LOGPAR_TYPE_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/allowed-fields.json" "${ENGINE_ALLOWED_FIELDS_PATH}/0"

    if [ ! -f "${ENGINE_SCHEMA_PATH}/0" ] || [ ! -f "${ENGINE_LOGPAR_TYPE_PATH}/0" ] || [ ! -f "${ENGINE_ALLOWED_FIELDS_PATH}/0" ]; then
        echo "Error: Failed to copy store files."
        exit 1
    fi

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${STORE_PATH}
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${KVDB_PATH}
    find ${STORE_PATH} -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
    find ${KVDB_PATH} -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;

    echo "Engine store installed successfully."

}

setForwarderConf()
{
    DEST_FULL_PATH=${INSTALLDIR}/etc/
    FORWARDER_SRC_PATH=./alert_forwarder

    echo "Copying forwarder alert config file..."
    cp "${FORWARDER_SRC_PATH}/alert_forwarder.conf" "${DEST_FULL_PATH}"

    if [ ! -f "${DEST_FULL_PATH}/alert_forwarder.conf" ] ; then
        echo "Error: Failed to copy forwarder alert config file."
        exit 1
    fi

    chown ${WAZUH_USER}:${WAZUH_GROUP} ${DEST_FULL_PATH}/alert_forwarder.conf
    chmod 640 ${DEST_FULL_PATH}/alert_forwarder.conf
}

InstallLocal()
{

    InstallCommon

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/var/multigroups
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/db
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/download
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/archives
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/alerts
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/firewall
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/api
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/rootcheck

    ${INSTALL} -m 0750 -o root -g 0 wazuh-monitord ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} verify-agent-conf ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 wazuh-regex ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 agent_control ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 wazuh-db ${INSTALLDIR}/bin/
    ${INSTALL} -m 0750 -o root -g 0 build/engine/wazuh-engine ${INSTALLDIR}/bin/wazuh-analysisd

    installEngineStore
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/tzdb

    ${INSTALL} -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} alert_forwarder/main.py ${INSTALLDIR}/bin/wazuh-forwarder
    setForwarderConf

    # TODO Deletes old ruleset and stats, rootcheck and SCA?

    InstallSecurityConfigurationAssessmentFiles "manager"

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/db

    if [ "X${OPTIMIZE_CPYTHON}" = "Xy" ]; then
        CPYTHON_FLAGS="OPTIMIZE_CPYTHON=yes"
    fi

    # Install Vulnerability Detector files
    ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/vd
    ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/indexer

    # Install templates files
    ${INSTALL} -d -m 0440 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/templates
    ${INSTALL} -m 0440 -o root -g ${WAZUH_GROUP} wazuh_modules/vulnerability_scanner/indexer/template/index-template.json ${INSTALLDIR}/templates/vd_states_template.json

    ${INSTALL} -m 0440 -o root -g ${WAZUH_GROUP} wazuh_modules/vulnerability_scanner/indexer/template/update-mappings.json ${INSTALLDIR}/templates/vd_states_update_mappings.json

    # Install Task Manager files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/tasks

    ### Install Python
    ${MAKEBIN} wpython INSTALLDIR=${INSTALLDIR} TARGET=${INSTYPE}

    ${MAKEBIN} --quiet -C ../framework install INSTALLDIR=${INSTALLDIR}

    ### Backup old API
    if [ "X${update_only}" = "Xyes" ]; then
      ${MAKEBIN} --quiet -C ../api backup INSTALLDIR=${INSTALLDIR} REVISION=${REVISION}
    fi

    ### Install API
    ${MAKEBIN} --quiet -C ../api install INSTALLDIR=${INSTALLDIR}

    ### Restore old API
    if [ "X${update_only}" = "Xyes" ]; then
      ${MAKEBIN} --quiet -C ../api restore INSTALLDIR=${INSTALLDIR} REVISION=${REVISION}
    fi
}

TransferShared()
{
    rm -f ${INSTALLDIR}/etc/shared/merged.mg
    find ${INSTALLDIR}/etc/shared -maxdepth 1 -type f -not -name ar.conf -not -name files.yml -exec cp -pf {} ${INSTALLDIR}/backup/shared \;
    find ${INSTALLDIR}/etc/shared -maxdepth 1 -type f -not -name ar.conf -not -name files.yml -exec mv -f {} ${INSTALLDIR}/etc/shared/default \;
}

checkDownloadContent()
{
    VD_FILENAME='vd_1.0.0_vd_4.13.0.tar.xz'
    VD_FULL_PATH=${INSTALLDIR}/tmp/${VD_FILENAME}

    if [ "X${DOWNLOAD_CONTENT}" = "Xy" ]; then
        echo "Download ${VD_FILENAME} file"
        wget -O ${VD_FULL_PATH} http://packages.wazuh.com/deps/vulnerability_model_database/${VD_FILENAME}

        chmod 640 ${VD_FULL_PATH}
        chown ${WAZUH_USER}:${WAZUH_GROUP} ${VD_FULL_PATH}
    fi
}

InstallServer()
{

    InstallLocal
    if [ -f external/jemalloc/lib/libjemalloc.so.2 ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} external/jemalloc/lib/libjemalloc.so.2 ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libjemalloc.so.2
        fi
    fi
    if [ -f build/shared_modules/router/librouter.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/shared_modules/router/librouter.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/librouter.so
        fi
    fi
    if [ -f build/shared_modules/content_manager/libcontent_manager.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/shared_modules/content_manager/libcontent_manager.so ${INSTALLDIR}/lib

        if ([ "X${DIST_NAME}" = "Xrhel" ] || [ "X${DIST_NAME}" = "Xcentos" ] || [ "X${DIST_NAME}" = "XCentOS" ]); then
            chcon -t textrel_shlib_t ${INSTALLDIR}/lib/libcontent_manager.so
        fi
    fi

    if [ -f build/shared_modules/indexer_connector/libindexer_connector.so ]
    then
        ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} build/shared_modules/indexer_connector/libindexer_connector.so ${INSTALLDIR}/lib

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

    # Check if the content needs to be downloaded.
    checkDownloadContent

    # Install cluster files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/cluster
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/logs/cluster

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/etc/shared/default
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/backup/shared

    TransferShared

    ${INSTALL} -m 0750 -o root -g 0 wazuh-remoted ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 wazuh-authd ${INSTALLDIR}/bin

    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/rids
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/router

    if [ ! -f ${INSTALLDIR}/queue/agents-timestamp ]; then
        ${INSTALL} -m 0600 -o root -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/queue/agents-timestamp
    fi

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/backup/agents
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/backup/db

    if [ ! -f ${INSTALLDIR}/etc/shared/default/agent.conf ]; then
        ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../etc/agent.conf ${INSTALLDIR}/etc/shared/default
    fi

    if [ ! -f ${INSTALLDIR}/etc/shared/agent-template.conf ]; then
        ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../etc/agent.conf ${INSTALLDIR}/etc/shared/agent-template.conf
    fi

    # Install the plugins files
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/__init__.py ${INSTALLDIR}/wodles/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/utils.py ${INSTALLDIR}/wodles/utils.py

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/buckets_s3
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/services
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/aws/subscribers
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/aws/aws_s3.py ${INSTALLDIR}/wodles/aws/aws-s3.py
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
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../framework/wrappers/generic_wrapper.sh ${INSTALLDIR}/wodles/aws/aws-s3

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud/buckets
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/gcloud/pubsub
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/gcloud.py ${INSTALLDIR}/wodles/gcloud/gcloud.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/integration.py ${INSTALLDIR}/wodles/gcloud/integration.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/tools.py ${INSTALLDIR}/wodles/gcloud/tools.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/exceptions.py ${INSTALLDIR}/wodles/gcloud/exceptions.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/buckets/bucket.py ${INSTALLDIR}/wodles/gcloud/buckets/bucket.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/buckets/access_logs.py ${INSTALLDIR}/wodles/gcloud/buckets/access_logs.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/gcloud/pubsub/subscriber.py ${INSTALLDIR}/wodles/gcloud/pubsub/subscriber.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../framework/wrappers/generic_wrapper.sh ${INSTALLDIR}/wodles/gcloud/gcloud

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/docker
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/docker-listener/DockerListener.py ${INSTALLDIR}/wodles/docker/DockerListener.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../framework/wrappers/generic_wrapper.sh ${INSTALLDIR}/wodles/docker/DockerListener

    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure/azure_services
    ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/wodles/azure/db
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure-logs.py ${INSTALLDIR}/wodles/azure/azure-logs.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_utils.py ${INSTALLDIR}/wodles/azure/azure_utils.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/__init__.py ${INSTALLDIR}/wodles/azure/azure_services/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/analytics.py ${INSTALLDIR}/wodles/azure/azure_services/analytics.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/graph.py ${INSTALLDIR}/wodles/azure/azure_services/graph.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/azure_services/storage.py ${INSTALLDIR}/wodles/azure/azure_services/storage.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/__init__.py ${INSTALLDIR}/wodles/azure/db/__init__.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/orm.py ${INSTALLDIR}/wodles/azure/db/orm.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../wodles/azure/db/utils.py ${INSTALLDIR}/wodles/azure/db/utils.py
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} ../framework/wrappers/generic_wrapper.sh ${INSTALLDIR}/wodles/azure/azure-logs

    GenerateAuthCert

    # Keystore
    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/keystore
    ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} wazuh-keystore ${INSTALLDIR}/bin/
}

InstallAgent()
{

    InstallCommon

    InstallSecurityConfigurationAssessmentFiles "agent"

    ${INSTALL} -m 0750 -o root -g 0 manage_agents ${INSTALLDIR}/bin
    ${INSTALL} -m 0750 -o root -g 0 wazuh-agentd ${INSTALLDIR}/bin

    ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/rids
    ${INSTALL} -d -m 0770 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/var/incoming
    ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../etc/wpk_root.pem ${INSTALLDIR}/etc/

    # Install the plugins files
    # Don't install the plugins if they are already installed. This check affects
    # hybrid installation mode
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
    elif [ "X$INSTYPE" = "Xserver" ]; then
        InstallServer
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        InstallLocal
    fi

}
