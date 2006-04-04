#!/bin/sh

# Generate windows packages
DIR=`dirname $0`;
FILE="win-files.txt"
CAT=`cat ${FILE}`
WINPKG="win-pkg"

# Going to the source dir
cd ${DIR}
CAT=`cat ${FILE}`
cd ..
mkdir ${WINPKG}

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
        source=""
        dest=""
    fi            
done    
