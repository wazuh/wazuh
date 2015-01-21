#!/bin/sh

set -e
set -u

if ! [ $# -eq 5 ]; then
    echo "Usage: ${0} USERNAME_DEFAULT USERNAME_MAIL USERNAME_REMOTE GROUPNAME DIRECTORY.";
    exit 1;
fi

echo "Wait for success..."

USER=$1
USER_MAIL=$2
USER_REM=$3
GROUP=$4
DIR=$5

UNAME=$(uname);

if [ "$UNAME" = "FreeBSD" -o "$UNAME" = "DragonFly" ]; then
    if ! grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1; then
        /usr/sbin/pw groupadd "${GROUP}"
        /usr/sbin/pw useradd "${USER}" -d "${DIR}" -s /sbin/nologin -g "${GROUP}"
        /usr/sbin/pw useradd "${USER_MAIL}" -d "${DIR}" -s /sbin/nologin -g "${GROUP}"
        /usr/sbin/pw useradd "${USER_REM}" -d "${DIR}" -s /sbin/nologin -g "${GROUP}"
    fi

elif [ "$UNAME" = "SunOS" ]; then
    if ! grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1; then
        /usr/sbin/groupadd "${GROUP}"
        /usr/sbin/useradd -d "${DIR}" -s /bin/false -g "${GROUP}" "${USER}"
        /usr/sbin/useradd -d "${DIR}" -s /bin/false -g "${GROUP}" "${USER_MAIL}"
        /usr/sbin/useradd -d "${DIR}" -s /bin/false -g "${GROUP}" "${USER_REM}"
    fi

elif [ "$UNAME" = "AIX" ]; then
    AIXSH=""

    if ls -la /bin/false > /dev/null 2>&1; then
        AIXSH="-s /bin/false"
    fi

    if ! grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1; then
        /usr/bin/mkgroup "${GROUP}"
        /usr/sbin/useradd -d "${DIR}" "${AIXSH}" -g "${GROUP}" "${USER}"
        /usr/sbin/useradd -d "${DIR}" "${AIXSH}" -g "${GROUP}" "${USER_MAIL}"
        /usr/sbin/useradd -d "${DIR}" "${AIXSH}" -g "${GROUP}" "${USER_REM}"
    fi

# Thanks Chuck L. for the mac addusers
elif [ "$UNAME" = "Darwin" ]; then
    if ! id -u "${USER}" > /dev/null 2>&1; then

        # Creating for <= 10.4
        if /usr/bin/sw_vers 2>/dev/null| grep "ProductVersion" | grep -E "10.2.|10.3|10.4" > /dev/null 2>&1; then
            chmod +x ./init/darwin-addusers.pl
            ./init/darwin-addusers.pl
        else
            chmod +x ./init/osx105-addusers.sh
            ./init/osx105-addusers.sh
        fi
    fi
else
    if ! grep "^${USER_REM}" /etc/passwd > /dev/null 2>&1; then
        /usr/sbin/groupadd "${GROUP}"

        # We first check if /sbin/nologin is present. If it is not,
        # we look for /bin/false. If none of them is present, we
        # just stick with nologin (no need to fail the install for that).
        OSMYSHELL="/sbin/nologin"
        if ! ls -la ${OSMYSHELL} > /dev/null 2>&1; then
            if ls -la /bin/false > /dev/null 2>&1; then
                OSMYSHELL="/bin/false"
            fi
        fi
        /usr/sbin/useradd -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${USER}"
        /usr/sbin/useradd -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${USER_MAIL}"
        /usr/sbin/useradd -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}" "${USER_REM}"
    fi
fi

echo "success";
exit 0;
