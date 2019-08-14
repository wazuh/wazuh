#!/bin/sh

#Copyright (C) 2015-2019, Wazuh Inc.

set -e
set -u

if ! [ $# -eq 6 ]; then
    echo "Usage: ${0} USERNAME_DEFAULT USERNAME_MAIL USERNAME_REMOTE GROUPNAME DIRECTORY INSTYPE.";
    exit 1;
fi

echo "Wait for success..."

USER=$1
USER_MAIL=$2
USER_REM=$3
GROUP=$4
DIR=$5
INSTYPE=$6

UNAME=$(uname);
# Thanks Chuck L. for the mac addusers
if [ "$UNAME" = "Darwin" ]; then
    if ! id -u "${USER}" > /dev/null 2>&1; then

        # Creating for <= 10.4
        if /usr/bin/sw_vers 2>/dev/null| grep "ProductVersion" | grep -E "10.2.|10.3|10.4" > /dev/null 2>&1; then
            chmod +x ./init/darwin-addusers.pl
            ./init/darwin-addusers.pl $USER $USER_MAIL $USER_REM $INSTYPE
        else
            chmod +x ./init/osx105-addusers.sh
            ./init/osx105-addusers.sh $USER $USER_MAIL $USER_REM $GROUP $INSTYPE
        fi
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

    if [ "X$INSTYPE" = "Xserver" ]; then
        NEWUSERS="${USER} ${USER_MAIL} ${USER_REM}"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        NEWUSERS="${USER} ${USER_MAIL}"
    else
        NEWUSERS=${USER}
    fi

    for U in ${NEWUSERS}; do
        if ! grep "^${U}" /etc/passwd > /dev/null 2>&1; then
            if [ "$UNAME" = "OpenBSD" -o "$UNAME" = "SunOS" -o "$UNAME" = "HP-UX" ]; then
                ${USERADD} -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${U}"
            elif [ "$UNAME" = "AIX" ]; then
                GID=$(cat /etc/group | grep ossec| cut -d':' -f 3)
                uid=$(( $GID + 1 ))
                echo "ossec:x:$uid:$GID::/var/ossec:/bin/false" >> /etc/passwd
            else
                ${USERADD} "${U}" -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}"
            fi
        fi
    done
fi

echo "success";
exit 0;
