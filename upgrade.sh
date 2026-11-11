#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

clean_upgrade_dir() {
    for file in ./var/upgrade/*; do
        [ "$file" = "./var/upgrade/upgrade_result" ] && continue
        rm -rf "$file"
    done
}

upgrade_log() {
    echo "$(date +"%Y/%m/%d %H:%M:%S") - $1" >> ./logs/upgrade.log
}

validate_config() {
    ./bin/wazuh-logcollector -t -c "$1" >> ./logs/upgrade.log 2>&1 && ./bin/wazuh-agentd -t -c "$1" >> ./logs/upgrade.log 2>&1
}

# Remove the default "df -P" command monitoring block from the local ossec.conf.
# A <localfile> block is dropped only when, ignoring indentation, it holds
# exactly <log_format>command</log_format> and <command>df -P</command>, plus
# optionally <frequency> and <alias>. Any other block, or one with comments or
# extra options, is kept as is. The agent restart done by pkg_installer.sh
# applies the new configuration.
remove_df_localfile() {
    local CONF="./etc/ossec.conf"
    local NEW_CONF BACKUP AWK_RESULT

    if [ -L "${CONF}" ]; then
        upgrade_log "df -P removal: ${CONF} is a symbolic link, refusing to edit it."
        return 1
    elif [ ! -f "${CONF}" ]; then
        upgrade_log "df -P removal: ${CONF} not found, skipping."
        return 0
    fi

    NEW_CONF=$(mktemp ./etc/.ossec.conf.XXXXXX) || {
        upgrade_log "df -P removal: cannot create a temporary file, configuration left unchanged."
        return 1
    }

    awk '
    function is_df_block(text) {
        if (sub(/<log_format>command<\/log_format>/, "", text) != 1) return 0
        if (sub(/<command>df -P<\/command>/, "", text) != 1) return 0
        sub(/<frequency>[0-9]+<\/frequency>/, "", text)
        sub(/<alias>[^<]*<\/alias>/, "", text)
        return text == "<localfile></localfile>"
    }
    BEGIN { removed = 0 }
    {
        if (skip_blank) {
            skip_blank = 0
            if ($0 ~ /^[ \t\r]*$/) next
        }
        if ($0 ~ /^[ \t]*<localfile>/) {
            if (inblock) printf "%s", block
            inblock = 1; block = ""; text = ""
        }
        if (inblock) {
            block = block $0 "\n"
            line = $0
            sub(/^[ \t]+/, "", line)
            sub(/[ \t\r]+$/, "", line)
            text = text line
            if ($0 ~ /<\/localfile>/) {
                inblock = 0
                if (is_df_block(text)) {
                    removed++
                    skip_blank = 1
                } else {
                    printf "%s", block
                }
                block = ""
            }
            next
        }
        print
    }
    END {
        printf "%s", block
        exit (removed > 0 ? 0 : 10)
    }' "${CONF}" > "${NEW_CONF}"
    AWK_RESULT=$?

    if [ ${AWK_RESULT} -eq 10 ]; then
        upgrade_log "df -P removal: no default df -P command block found in ${CONF}, nothing to do."
        rm -f "${NEW_CONF}"
        return 0
    elif [ ${AWK_RESULT} -ne 0 ] || [ ! -s "${NEW_CONF}" ]; then
        upgrade_log "df -P removal: failed to process ${CONF} (awk result ${AWK_RESULT}), configuration left unchanged."
        rm -f "${NEW_CONF}"
        return 1
    fi

    if ! validate_config "${CONF}"; then
        upgrade_log "df -P removal: the current configuration does not pass validation, configuration left unchanged."
        rm -f "${NEW_CONF}"
        return 1
    elif ! validate_config "${NEW_CONF}"; then
        upgrade_log "df -P removal: the edited configuration does not pass validation, configuration left unchanged."
        rm -f "${NEW_CONF}"
        return 1
    fi

    # Give the new file and the backup the owner, mode and SELinux context of
    # the original, then swap the new file in with an atomic rename.
    BACKUP=$(mktemp ./etc/ossec.conf.before-df-removal.XXXXXX) && cat "${CONF}" > "${BACKUP}" \
        && chown --reference="${CONF}" "${NEW_CONF}" "${BACKUP}" \
        && chmod --reference="${CONF}" "${NEW_CONF}" "${BACKUP}" || {
        upgrade_log "df -P removal: cannot prepare the new configuration or its backup, configuration left unchanged."
        rm -f "${NEW_CONF}" "${BACKUP}"
        return 1
    }
    if command -v chcon >/dev/null 2>&1; then
        chcon --reference="${CONF}" "${NEW_CONF}" "${BACKUP}" 2>/dev/null
    fi

    if ! mv -f "${NEW_CONF}" "${CONF}"; then
        upgrade_log "df -P removal: cannot replace ${CONF}, configuration left unchanged."
        rm -f "${NEW_CONF}" "${BACKUP}"
        return 1
    fi

    upgrade_log "df -P removal: block removed from ${CONF}, backup saved as ${BACKUP}."
    return 0
}

# validate OS, linux or macos
if [ "X$(uname)" = "XLinux" ] ; then
    # Get Wazuh installation path
    SCRIPT=$(readlink -f "$0")
    WAZUH_HOME=$(dirname $(dirname $(dirname "$SCRIPT")))
    cd "${WAZUH_HOME}"
    # Abort before the package installation if the configuration could not be
    # edited, so the manager reports the upgrade as failed.
    remove_df_localfile || exit 1
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && clean_upgrade_dir) >> ./logs/upgrade.log 2>&1 &
else
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && clean_upgrade_dir) >> ./logs/upgrade.log 2>&1 &
fi
