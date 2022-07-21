#!/bin/sh

#Copyright (C) 2015, Wazuh Inc.

set -e
set -u

if ! [ $# -eq 1 ]; then
    echo "Usage: ${0} GROUPNAME.";
    exit 1;
fi

echo "Wait for success..."

USER=ossec
USER_MAIL=ossecm
USER_REM=ossecr
GROUP=$1

UNAME=$(uname);
if [ "$UNAME" = "Darwin" ]; then
    if id -u "${USER}" > /dev/null 2>&1; then
        chmod +x ./src/init/darwin-delete-oldusers.sh
        ./src/init/darwin-delete-oldusers.sh $GROUP
    fi

else
    if [ "$UNAME" = "FreeBSD" -o "$UNAME" = "DragonFly" ]; then
        GROUPDEL="/usr/sbin/pw groupdel"
        USERDEL="/usr/sbin/pw userdel"
    elif [ "$UNAME" = "SunOS" -o "$UNAME" = "OpenBSD" -o "$UNAME" = "HP-UX" -o "$UNAME" = "NetBSD" ]; then
        GROUPDEL="/usr/sbin/groupdel"
        USERDEL="/usr/sbin/userdel"
    elif [ "$UNAME" = "AIX" ]; then
        GROUPDEL="/usr/bin/rmgroup"
        USERDEL="/usr/sbin/userdel"
    else
        # All current linux distributions should support system accounts for
        # users/groups. If not, leave the GROUPDEL/USERDEL as it was before
        # this change
        sys_acct_chk () {
            $1 --help 2>&1 | grep -e " *-r.*system account" >/dev/null 2>&1 && echo "$1 -r" || echo "$1"
        }
        GROUPDEL=$(sys_acct_chk "/usr/sbin/groupdel")
        USERDEL=$(sys_acct_chk "/usr/sbin/userdel")
    fi

    OSSECUSERS="${USER_REM} ${USER_MAIL} ${USER}"

    for U in ${OSSECUSERS}; do
        if grep "^${U}" /etc/passwd > /dev/null 2>&1; then
            ${USERDEL} "${U}"
        fi
    done

    if grep "^${GROUP}:" /etc/group > /dev/null 2>&1; then
        ${GROUPDEL} "${GROUP}"
    fi
fi

echo "success";
exit 0;
