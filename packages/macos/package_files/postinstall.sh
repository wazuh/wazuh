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

    # The backup holds only a regular file per config name (preinstall copied with cp -R and
    # removed any planted symlink or hard link before the payload was laid). Move it over the
    # package default with a plain mv: -h is not used because it does not exist before macOS 12.5
    # (Apple file_cmds-353) and the agent supports older releases, and by this point the destination
    # is the package's regular file, not a symlink. Anything that is not a regular file is dropped.
    restore_failed=""
    for conf in ossec.conf client.keys local_internal_options.conf; do
        if [ ! -e ${DIR}/config_files/${conf} ] && [ ! -L ${DIR}/config_files/${conf} ]; then
            continue
        elif [ -f ${DIR}/config_files/${conf} ] && [ ! -L ${DIR}/config_files/${conf} ]; then
            if ! mv -f ${DIR}/config_files/${conf} ${DIR}/etc/${conf}; then
                echo "WARNING: could not restore ${DIR}/etc/${conf}; a copy is kept for recovery." >&2
                restore_failed="yes"
            fi
        else
            echo "WARNING: ${DIR}/config_files/${conf} is not a regular file; not restored, the package-installed ${DIR}/etc/${conf} is left in place." >&2
            rm -rf ${DIR}/config_files/${conf}
        fi
    done

    # etc/shared is a directory: replace the package copy with the backup without destroying it
    # first. Move the installed one aside, move the backup into place, and put the original back if
    # that fails, so a failed move never leaves etc/shared missing (and no mv -h, as above).
    if [ -d ${DIR}/config_files/shared ] && [ ! -L ${DIR}/config_files/shared ]; then
        rm -rf ${DIR}/etc/shared.save
        mv -f ${DIR}/etc/shared ${DIR}/etc/shared.save 2> /dev/null
        if mv -f ${DIR}/config_files/shared ${DIR}/etc/shared; then
            rm -rf ${DIR}/etc/shared.save
        else
            [ -e ${DIR}/etc/shared.save ] && mv -f ${DIR}/etc/shared.save ${DIR}/etc/shared
            echo "WARNING: could not restore ${DIR}/etc/shared; a copy is kept for recovery." >&2
            restore_failed="yes"
        fi
    elif [ -e ${DIR}/config_files/shared ] || [ -L ${DIR}/config_files/shared ]; then
        echo "WARNING: ${DIR}/config_files/shared is not a directory; not restored, the package-installed ${DIR}/etc/shared is left in place." >&2
        rm -rf ${DIR}/config_files/shared
    fi

    # Drop the backup once everything was restored or deliberately dropped. If a restore failed,
    # keep what is left under a name the next upgrade's preinstall will not wipe, so an operator
    # can still recover it after re-running the installer (only the first such run is preserved; a
    # later failure is cleaned by the next preinstall).
    if [ -z "${restore_failed}" ]; then
        rm -rf ${DIR}/config_files/
    elif [ ! -e ${DIR}/config_files.unrestored ]; then
        mv ${DIR}/config_files ${DIR}/config_files.unrestored \
            && echo "WARNING: configuration that could not be restored is kept at ${DIR}/config_files.unrestored for recovery." >&2
    fi
fi

# harden_tree MODE OWNER DIR: set MODE and OWNER on DIR and everything under it, acting only on a
# directory or a single-link entry — never on a symlink or on anything with more than one hard link
# (a regular file, FIFO or socket the wazuh account may have linked to something outside the
# install), so chmod/chown cannot reach that external inode. macOS has no protected_hardlinks, so
# every recursive step over a wazuh-writable tree goes through this.
harden_tree() {
    find "$3" ! -type l \( -type d -o -links 1 \) -exec chmod "$1" {} + -exec chown "$2" {} +
}

# Default for all directories. Parts of the tree (etc/, logs/, var/, queue/ sub-dirs) are writable
# by the wazuh account, so the hard-link-safe walk is used instead of a plain chmod -R / chown -R.
echo "Seting permissions and ownership for directories and files"
harden_tree 750 root:${GROUP} ${DIR}

chown -R root:wheel ${DIR}/bin
chown -R root:wheel ${DIR}/lib

# The ossec queue (default for agentd to read). queue/{alerts,sockets} are group-writable, so a
# hard link the wazuh account plants inside them must be skipped, not chowned/chmodded through.
harden_tree 770 ${USER}:${GROUP} ${DIR}/queue/alerts
harden_tree 770 ${USER}:${GROUP} ${DIR}/queue/sockets
harden_tree 750 ${USER}:${GROUP} ${DIR}/queue/diff
harden_tree 750 ${USER}:${GROUP} ${DIR}/queue/rids

# For the logging user. logs/ is writable by the wazuh account, so the chown and the file chmod
# must skip a hard link it may have planted there, whose target would otherwise be re-owned and
# re-moded. Directories cannot be hard-linked by an unprivileged user.
chmod 770 ${DIR}/logs
find ${DIR}/logs ! -type l \( -type d -o -links 1 \) -exec chown ${USER}:${GROUP} {} +
find ${DIR}/logs/ -type d -exec chmod 750 {} +
find ${DIR}/logs/ -type f -links 1 -exec chmod 660 {} +

# tmp is 1750 (not group-writable), so nothing can be planted in it; keep the chown off any hard
# link anyway, for consistency with the walks above.
find ${DIR}/tmp ! -type l \( -type d -o -links 1 \) -exec chown root:${GROUP} {} +
chmod 1750 ${DIR}/tmp

chmod 770 ${DIR}/etc
chown ${USER}:${GROUP} ${DIR}/etc
# etc/ is owned by the wazuh account, so a file in it may be a link that account planted. Set the
# mode and owner only on a regular file with a single hard link that is not a symlink, so a planted
# symlink or hard link (macOS has no protected_hardlinks) leaves its target untouched.
harden_etc_file() {
    if [ -f "$2" ] && [ ! -L "$2" ] && [ -n "$(find "$2" -prune -links 1 2>/dev/null)" ]; then
        chmod "$1" "$2"
        [ "${3:-}" = nochown ] || chown root:${GROUP} "$2"
    fi
}
harden_etc_file 640 ${DIR}/etc/internal_options.conf
harden_etc_file 640 ${DIR}/etc/local_internal_options.conf
harden_etc_file 640 ${DIR}/etc/client.keys
harden_etc_file 640 ${DIR}/etc/localtime nochown
# etc/shared only when it is a real directory (a trailing-slash find would follow a symlinked
# shared into its target); inside it skip a symlink and a hard-linked file, so chown/chmod cannot
# reach a file outside the installation.
if [ -d ${DIR}/etc/shared ] && [ ! -L ${DIR}/etc/shared ]; then
    chmod 770 ${DIR}/etc/shared # ossec must be able to write to it
    find ${DIR}/etc/shared ! -type l \( -type d -o -links 1 \) -exec chown root:${GROUP} {} +
    find ${DIR}/etc/shared -type f -links 1 -exec chmod 660 {} +
fi
harden_etc_file 660 ${DIR}/etc/ossec.conf
harden_etc_file 640 ${DIR}/etc/wpk_root.pem

chmod 770 ${DIR}/.ssh

# For the /var/run. var/{incoming,upgrade} are group-writable, so use the hard-link-safe walk.
harden_tree 770 root:${GROUP} ${DIR}/var

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

    if [ -f "${INSTALLATION_SCRIPTS_DIR}/gen_ossec.sh" ]; then
        ${INSTALLATION_SCRIPTS_DIR}/gen_ossec.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} ${DIR} > ${DIR}/etc/ossec.conf
        chown root:wazuh ${DIR}/etc/ossec.conf
        chmod 0640 ${DIR}/etc/ossec.conf
    else
        echo "Error: ${INSTALLATION_SCRIPTS_DIR}/gen_ossec.sh script not found."
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

# Remove 4.1.5 patch
if [ -f ${DIR}/queue/alerts/sockets ]; then
    echo "Removing 4.1.5 patch file socket"
    rm ${DIR}/queue/alerts/sockets
fi

if [ -n "${upgrade}" ] && [ -n "${restart}" ]; then
    echo "Restarting Wazuh..."
    launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.agent.plist
fi
