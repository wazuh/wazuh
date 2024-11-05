#!/bin/sh
# postinst script for wazuh-agent
# Wazuh, Inc 2015

install_path="<INSTALL_PATH>"
osversion=$(uname -v)
SCA_BASE_DIR="${install_path}/ruleset/sca/"
SCA_TMP_DIR="${install_path}/tmp/sca"

if [ -d ${install_path}/logs/ossec ]; then
  if [ -z "$(ls -A ${install_path}/logs/ossec)" ]; then
    rm -rf ${install_path}/logs/ossec
  else
    rm -rf ${install_path}/logs/wazuh
    mv ${install_path}/logs/ossec ${install_path}/logs/wazuh
  fi
fi
if [ -d ${install_path}/queue/ossec ]; then
  if [ -z "$(ls -A ${install_path}/queue/ossec)" ]; then
    rm -rf ${install_path}/queue/ossec
  else
    rm -rf ${install_path}/queue/sockets
    mv ${install_path}/queue/ossec/ ${install_path}/queue/sockets
  fi
fi

# Remove old ossec user and group if exists and change ownwership of files
if grep "^ossec:" /etc/group > /dev/null 2>&1; then
  find ${install_path}/ -group ossec -user root -exec chown root:wazuh {} \; > /dev/null 2>&1 || true
  if grep "^ossec" /etc/passwd > /dev/null 2>&1; then
    find ${install_path}/ -group ossec -user ossec -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossec
  fi
  if grep "^ossecm" /etc/passwd > /dev/null 2>&1; then
    find ${install_path}/ -group ossec -user ossecm -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossecm
  fi
  if grep "^ossecr" /etc/passwd > /dev/null 2>&1; then
    find ${install_path}/ -group ossec -user ossecr -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
    userdel ossecr
  fi
  groupdel ossec
fi

if [ -d "${SCA_TMP_DIR}/sunos/5/${osversion}" ]; then
  scalist="${SCA_TMP_DIR}/sunos/5/${osversion}/sca.files"
else
  scalist="${SCA_TMP_DIR}/sunos/5/11/sca.files"
fi

for sca_file in $(cat ${scalist}); do
  if [ -f ${SCA_TMP_DIR}/${sca_file} ]; then
    mv ${SCA_TMP_DIR}/${sca_file} ${SCA_BASE_DIR}
  fi
done

rm -rf ${install_path}/logs/ossec/
rm -rf ${install_path}/queue/ossec/
rm -rf ${SCA_TMP_DIR}

# Remove upgrade files after install/upgrade
rm -rf ${install_path}/installation_scripts/
rm -rf /lib/svc/manifest/site/post-install.xml
