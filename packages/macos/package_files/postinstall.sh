#! /bin/bash
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott
# Modified by Santiago Bassett (http://www.wazuh.com) - Feb 2016
# alterations by bil hays 2013
# -Switched to bash
# -Added some sanity checks
# -Added routine to find the first 3 contiguous UIDs above 100,
#  starting at 600 puts this in user space
# -Added lines to append the ossec users to the group ossec
#  so the the list GroupMembership works properly
GROUP="wazuh"
USER="wazuh"
DIR="/Library/Ossec"
INSTALLATION_SCRIPTS_DIR="${DIR}/packages_files/agent_installation_scripts"
SCA_BASE_DIR="${INSTALLATION_SCRIPTS_DIR}/sca"
UPGRADE_FILE_FLAG="${DIR}/WAZUH_PKG_UPGRADE"


if [ -f "${DIR}/WAZUH_RESTART" ]; then
    restart="true"
    rm -f ${DIR}/WAZUH_RESTART
fi

if [ -f "${UPGRADE_FILE_FLAG}" ]; then
    upgrade="true"
    rm -f ${UPGRADE_FILE_FLAG}
    echo "Restoring configuration files from ${DIR}/config_files/ to ${DIR}/etc/"
    rm -rf ${DIR}/etc/{ossec.conf,client.keys,local_internal_options.conf,shared}
    cp -rf ${DIR}/config_files/{ossec.conf,client.keys,local_internal_options.conf,shared} ${DIR}/etc/
    rm -rf ${DIR}/config_files/
fi

# Default for all directories
echo "Seting permissions and ownership for directories and files"
chmod -R 750 ${DIR}/
chown -R root:${GROUP} ${DIR}/

chown -R root:wheel ${DIR}/bin
chown -R root:wheel ${DIR}/lib

# To the ossec queue (default for agentd to read)
chown -R ${USER}:${GROUP} ${DIR}/queue/{diff,sockets,rids}

chmod -R 770 ${DIR}/queue/sockets
chmod -R 750 ${DIR}/queue/{diff,rids}

# For the logging user
chmod 770 ${DIR}/logs
chown -R ${USER}:${GROUP} ${DIR}/logs
find ${DIR}/logs/ -type d -exec chmod 750 {} \;
find ${DIR}/logs/ -type f -exec chmod 660 {} \;

chown -R root:${GROUP} ${DIR}/tmp
chmod 1750 ${DIR}/tmp

chmod 770 ${DIR}/etc
chown ${USER}:${GROUP} ${DIR}/etc
chmod 640 ${DIR}/etc/internal_options.conf
chown root:${GROUP} ${DIR}/etc/internal_options.conf
chmod 640 ${DIR}/etc/local_internal_options.conf
chown root:${GROUP} ${DIR}/etc/local_internal_options.conf
chmod 640 ${DIR}/etc/client.keys
chown root:${GROUP} ${DIR}/etc/client.keys
chmod 640 ${DIR}/etc/localtime
chmod 770 ${DIR}/etc/shared # ossec must be able to write to it
chown -R root:${GROUP} ${DIR}/etc/shared
find ${DIR}/etc/shared/ -type f -exec chmod 660 {} \;
chown root:${GROUP} ${DIR}/etc/ossec.conf
chmod 640 ${DIR}/etc/ossec.conf
chown root:${GROUP} ${DIR}/etc/wpk_root.pem
chmod 640 ${DIR}/etc/wpk_root.pem

# For the /var/run
chmod -R 770 ${DIR}/var
chown -R root:${GROUP} ${DIR}/var

# VERSION.json
chmod -R 440 ${DIR}/VERSION.json
chown -R ${USER}:${GROUP} ${DIR}/VERSION.json

# Check if the distribution detection script exists
if [ -f "${INSTALLATION_SCRIPTS_DIR}/src/init/dist-detect.sh" ]; then
    echo "Running the dist-detect.sh script..."
    . "${INSTALLATION_SCRIPTS_DIR}/src/init/dist-detect.sh"
else
    echo "Error: dist-detect.sh script not found."
fi

if [ -z "${upgrade}" ]; then
    echo "Generating Wazuh configuration for a fresh installation."

    if [ -f "${INSTALLATION_SCRIPTS_DIR}/src/init/gen_wazuh.sh" ]; then
        ${INSTALLATION_SCRIPTS_DIR}/src/init/gen_wazuh.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} ${DIR} > ${DIR}/etc/ossec.conf
        chown root:wazuh ${DIR}/etc/ossec.conf
        chmod 0640 ${DIR}/etc/ossec.conf
    else
        echo "Error: ${INSTALLATION_SCRIPTS_DIR}/src/init/gen_wazuh.sh script not found."
    fi
fi

SCA_DIR="${DIST_NAME}/${DIST_VER}"
mkdir -p ${DIR}/ruleset/sca

SCA_TMP_DIR="${SCA_BASE_DIR}/${SCA_DIR}"

# Install the configuration files needed for this hosts
echo "Installing SCA configuration files..."
if [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}"
else
    SCA_TMP_DIR="${SCA_BASE_DIR}/generic"
fi

SCA_TMP_FILE="${SCA_TMP_DIR}/sca.files"

if [ -r ${SCA_TMP_FILE} ]; then

    rm -f ${DIR}/ruleset/sca/* || true

    for sca_file in $(cat ${SCA_TMP_FILE}); do
        mv ${SCA_BASE_DIR}/${sca_file} ${DIR}/ruleset/sca
    done
fi

# Register and configure agent if Wazuh environment variables are defined
if [ -z "${upgrade}" ]; then
    echo "Running the register_configure_agent.sh script..."
    if [ -f "${INSTALLATION_SCRIPTS_DIR}/src/init/register_configure_agent.sh" ]; then
        ${INSTALLATION_SCRIPTS_DIR}/src/init/register_configure_agent.sh ${DIR} > /dev/null || :
    else
        echo "Error: ${INSTALLATION_SCRIPTS_DIR}/src/init/register_configure_agent.sh script not found."
    fi
fi

# Remove backup file created in register_configure_agent step
if [ -e ${DIR}/etc/ossec.confre ]; then
    rm -f ${DIR}/etc/ossec.confre || true
fi

# Install the service
echo "Running the darwin-init.sh script..."
if [ -f "${INSTALLATION_SCRIPTS_DIR}/src/init/darwin-init.sh" ]; then
    ${INSTALLATION_SCRIPTS_DIR}/src/init/darwin-init.sh ${DIR}
else
    echo "Error: ${INSTALLATION_SCRIPTS_DIR}/src/init/darwin-init.sh script not found."
fi

# Remove temporary directory
echo "Removing temporary files..."
rm -rf ${DIR}/packages_files

# Remove old ossec user and group if exists and change ownwership of files
if [[ $(dscl . -read /Groups/ossec) ]]; then
    echo "Changing group from Ossec to Wazuh"
    find ${DIR}/ -group ossec -user root -exec chown root:wazuh {} \; > /dev/null 2>&1 || true
    if [[ $(dscl . -read /Users/ossec) ]]; then
        echo "Changing user from Ossec to Wazuh"
        find ${DIR}/ -group ossec -user ossec -exec chown wazuh:wazuh {} \; > /dev/null 2>&1 || true
        echo "Removing Ossec user"
        sudo /usr/bin/dscl . -delete "/Users/ossec"
    fi
    echo "Removing Ossec group"
    sudo /usr/bin/dscl . -delete "/Groups/ossec"
fi

# Remove execq folder
if [ -S ${DIR}/queue/alerts/execq ]; then
    rm -f ${DIR}/queue/alerts/execq
fi

# Remove deprecated cfgaq socket
if [ -S ${DIR}/queue/alerts/cfgaq ]; then
    rm -f ${DIR}/queue/alerts/cfgaq
fi

# Remove alerts folder
if [ -d ${DIR}/queue/alerts ]; then
    rm -rf ${DIR}/queue/alerts
fi

# Remove deprecated binaries
if [ -f ${DIR}/bin/agent-auth ]; then
  rm -f ${DIR}/bin/agent-auth
fi

# #39064: drop the fleet-wide enrollment password. It is one secret that enrols any endpoint, left
# at rest on every one of them; 5.0 replaces it with an enrollment token for the first credential
# and a per-agent re-enrollment secret thereafter. A fresh 5.0 install never creates the file, so
# without this an upgraded host -- the longest-running one in the estate, which is exactly where
# the exposure matters most -- would keep it for ever.
#
# Upgrade only, and once: this is a package decision, not a runtime one, so it must not depend on
# the agent ever reaching a manager. Overwritten before it is unlinked, because the bytes are a
# secret. The issue names the DEB and RPM hooks; macOS carries the identical exposure.
if [ -n "${upgrade}" ] && [ -f ${DIR}/etc/authd.pass ]; then
  if [ -s ${DIR}/etc/authd.pass ]; then
    dd if=/dev/zero of=${DIR}/etc/authd.pass bs=1 count=$(wc -c < ${DIR}/etc/authd.pass) conv=notrunc > /dev/null 2>&1 || true
  fi
  rm -f ${DIR}/etc/authd.pass
  echo "wazuh-agent: removed the fleet-wide enrollment password at ${DIR}/etc/authd.pass. 5.0 enrols with an enrollment token (WAZUH_ENROLLMENT_TOKEN) and re-enrols with a per-agent secret."
fi

if [ -n "${upgrade}" ] && [ -n "${restart}" ]; then
    echo "Restarting Wazuh..."
    launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.agent.plist
fi
