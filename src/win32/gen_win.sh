#!/bin/sh

# Generate windows packages
DIR=`dirname $0`;
FILE="win-files.txt"
CAT=`cat ${FILE}`
WINPKG="win-pkg"

# Generating configs
./unix2dos.pl ossec.conf > ossec-win.conf
./unix2dos.pl help.txt > help_win.txt
./unix2dos.pl ../../etc/internal_options.conf > internal_options-win.conf
./unix2dos.pl ../../etc/local_internal_options-win.conf > local_internal_options-win.conf
./unix2dos.pl ../../LICENSE > LICENSE.txt
./unix2dos.pl ../../active-response/win/route-null.cmd > route-null.cmd
./unix2dos.pl ../../active-response/win/restart-ossec.cmd > restart-ossec.cmd

# Going to the source dir
cd ${DIR}
CAT=`cat ${FILE}`
cd ..
mkdir ${WINPKG}
mkdir ${WINPKG}/setup

source=""
dest=""
for i in ${CAT}; do
    echo $i;
    if [ "X${source}" = "X" ]; then
        source=$i;
    elif [ "X${dest}" = "X" ]; then
        dest=$i;
        echo "cp -pr ${source} ${WINPKG}/${dest}"
        cp -pr ${source} "${WINPKG}/${dest}"
        if [ ! $? = 0 ]; then
            echo "Error copying ${source} to ${WINPKG}/${dest}"
            exit 1;
        fi
        source=""
        dest=""
    fi
done

# Final cleanup, -f will ignore if files do not exist
rm -f ${WINPKG}/os_crypto/md5/main.c
rm -f ${WINPKG}/os_crypto/blowfish/main.c
rm -f ${WINPKG}/os_crypto/sha1/main.c
rm -f ${WINPKG}/os_crypto/md5_sha1/main.c
rm -f ${WINPKG}/shared/rules_op.c
