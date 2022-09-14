#!/bin/sh

#Copyright (C) 2015, Wazuh Inc.

set -e
set -u

if ! [ $# -eq 3 ]; then
    echo "Usage: ${0} USERNAME_DEFAULT GROUPNAME DIRECTORY.";
    exit 1;
fi

echo "Wait for success..."

USER=$1
GROUP=$2
DIR=$3

UNAME=$(uname);
# Thanks Chuck L. for the mac addusers
if [ "$UNAME" = "Darwin" ]; then
    if ! id -u "${USER}" > /dev/null 2>&1; then
        chmod +x ./init/darwin-addusers.sh
        ./init/darwin-addusers.sh $USER $GROUP $DIR
    fi

else
    if [ "$UNAME" = "FreeBSD" -o "$UNAME" = "DragonFly" ]; then
        GROUPADD="/usr/sbin/pw groupadd"
        USERADD="/usr/sbin/pw useradd"
        OSMYSHELL="/sbin/nologin"
    elif [ "$UNAME" = "SunOS" -o "$UNAME" = "OpenBSD" ]; then
        GROUPADD="/usr/sbin/groupadd"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/bin/false"
    elif [ "$UNAME" = "HP-UX" ]; then
        GROUPADD="/usr/sbin/groupadd"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/bin/false"
    elif [ "$UNAME" = "AIX" ]; then
        GROUPADD="/usr/bin/mkgroup"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/bin/false"
    elif [ "$UNAME" = "NetBSD" ]; then
        GROUPADD="/usr/sbin/groupadd"
        USERADD="/usr/sbin/useradd"
        OSMYSHELL="/sbin/nologin"
    elif [ $(grep "Alpine Linux" /etc/os-release > /dev/null  && echo 1) ]; then
        GROUPADD="/usr/sbin/addgroup -S"
        USERADD="/usr/sbin/adduser -S"
        OSMYSHELL="/sbin/nologin"
    else
    # All current linux distributions should support system accounts for
    # users/groups. If not, leave the GROUPADD/USERADD as it was before
    # this change
    sys_acct_chk () {
        $1 --help 2>&1 | grep -e " *-r.*system account" >/dev/null 2>&1 && echo "$1 -r" || echo "$1"
      }
    GROUPADD=$(sys_acct_chk "/usr/sbin/groupadd -f")
    USERADD=$(sys_acct_chk "/usr/sbin/useradd")
        OSMYSHELL="/sbin/nologin"
    fi

    if ! grep "^${GROUP}:" /etc/group > /dev/null 2>&1; then
        ${GROUPADD} "${GROUP}"
    fi

    if [ "${OSMYSHELL}" = "/sbin/nologin" ]; then
        # We first check if /sbin/nologin is present. If it is not,
        # we look for /bin/false. If none of them is present, we
        # just stick with nologin (no need to fail the install for that).
        if [ ! -f ${OSMYSHELL} ]; then
            if [ -f /bin/false ]; then
                OSMYSHELL="/bin/false"
            fi
        fi
    fi

    if ! grep "^${USER}:" /etc/passwd > /dev/null 2>&1; then
        if [ "$UNAME" = "OpenBSD" -o "$UNAME" = "SunOS" -o "$UNAME" = "HP-UX" -o "$UNAME" = "NetBSD" ]; then
            ${USERADD} -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${USER}"
        elif [ "$UNAME" = "AIX" ]; then
            GID=$(cat /etc/group | grep wazuh| cut -d':' -f 3)
            uid=$(( $GID + 1 ))
            echo "${USER}:x:$uid:$GID::${DIR}:/bin/false" >> /etc/passwd
        elif [ $(grep "Alpine Linux" /etc/os-release > /dev/null  && echo 1) ]; then
            ${USERADD} "${USER}" -h "${DIR}" -s ${OSMYSHELL} -G "${GROUP}"
        else
            ${USERADD} "${USER}" -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}"
        fi
    fi
fi

echo "success";
exit 0;
