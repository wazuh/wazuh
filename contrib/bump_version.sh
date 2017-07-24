#!/bin/bash

# Bump source version
# Wazuh Inc.
# May 2, 2017

# Syntax:
# bump_version [ <version> ] [ -r <revision> ] [ -p <product_version> ]
# Example:
# ./bump_version.sh v3.0.0-alpha1 -r 3457 -p 3.0.0.1

while [ -n "$1" ]
do
    case $1 in
    "-p")
        if [[ $2 =~ ^[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+$ ]]
        then
            product=$2
        else
            echo "Error: product does not match 'X.X.X.X'"
            exit 1
        fi

        shift 2
        ;;
    "-r")
        if [[ $2 =~ ^[[:digit:]]+$ ]]
        then
            revision=$2
        else
            echo "Error: revision is not numeric."
            exit 1
        fi

        shift 2
        ;;
    *)
        if [[ $1 =~ ^v[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(-[[:alnum:]]+)?$ ]]
        then
            version=$1
        else
            echo "Error: incorrect version (must have form 'vX.X.X' or 'vX.X.X-...')."
            exit 1
        fi

        shift 1
    esac
done

if [ -z "$version" ] && [ -z "$revision" ] && [ -z "$product" ]
then
    echo "Error: no arguments given."
    echo "Syntax: $0 [ <version> ] [ -r <revision> ] [ -p <product_version> ]"
    exit 1
fi

cd $(dirname $0)

VERSION_FILE="../src/VERSION"
REVISION_FILE="../src/REVISION"
DEFS_FILE="../src/headers/defs.h"
HELP_FILE="../src/win32/help.txt"
NSIS_FILE="../src/win32/ossec-installer.nsi"

if [ -n "$version" ]
then

    # File VERSIONS

    echo $version > $VERSION_FILE

    # File defs.h

    egrep "^#define __ossec_version +\"v.+\"" $DEFS_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable version definition found at file $DEFS_FILE"
        exit 1
    fi

    sed -E -i'' "s/^(#define __ossec_version +)\"v.*\"/\1\"$version\"/" $DEFS_FILE

    # File help.txt

    egrep "^\*\* .+ \*\*" $HELP_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable version definition found at file $HELP_FILE"
        exit 1
    fi

    sed -E -i'' "s/^(\*\* .+ )v.+ \*\*/\1$version \*\*/g" $HELP_FILE

    # File ossec-installer.nsi

    egrep "^\!define VERSION \".+\"" $NSIS_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable version definition found at file $NSIS_FILE"
        exit 1
    fi

    sed -E -i'' "s/^(\!define VERSION \").+\"/\1${version:1}\"/g" $NSIS_FILE
fi

if [ -n "$revision" ]
then

    # File REVISION

    echo $revision > $REVISION_FILE

    # File ossec-installer.nsi

    egrep "^\!define REVISION \".+\"" $NSIS_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable revision definition found at file $NSIS_FILE"
        exit 1
    fi

    sed -E -i'' "s/^(\!define REVISION \").+\"/\1$revision\"/g" $NSIS_FILE
fi

if [ -n "$product" ]
then

    # File ossec-installer.nsi

    egrep "^VIProductVersion \".+\"" $NSIS_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable product definition found at file $NSIS_FILE"
        exit 1
    fi

    sed -E -i'' "s/^(VIProductVersion \").+\"/\1$product\"/g" $NSIS_FILE
fi
