#!/bin/bash

SRC_DIR=`realpath $(dirname "$0")`
OUTPUT_DIR=`realpath $(mktemp -d -t wazuh-rtr-XXXXXX)`
CONTAINER_NAME=wazuh-rtr-engine
RTR_DIR=$SRC_DIR/.rtr
RTR_BIN=rtr.py
RTR_CONFIG="rtr_inputs/rtr_cicd.json"
CURRENT_UID_GID=$(id -u -n):$(id -g -n)
PERMISSIONS_BACKUP_FILE=/tmp/permissions.acl
USERNAME=`logname`
USERID=`id -u $USERNAME`
GROUPID=`id -g $USERNAME`
VERBOSE=''
BUILD_DOCKER="yes"

build() {
    docker build -f .rtr/Dockerfile -t $CONTAINER_NAME -q . > /dev/null
}

Help() {
    # Display Help
    echo "Run RTR on a directory."
    echo
    echo "Syntax: rtr.sh [-h|o|s|i|v|b]"
    echo "options:"
    echo "h     Print this Help."
    echo "o     Output directory. It creates a temporary directory in '/tmp/wazuh-rtr-XXXXXX' if not specified."
    echo "s     Source directory. It uses the directory of this scripts if not specified."
    echo "i     RTR input file. By default, it uses 'rtr_inputs/rtr_cicd.json'."
    echo "v     Verbose. Enables debug mode for RTR."
    echo "b     Build docker. By default, it builds the docker image. Set to 'no' to skip the build."
    echo ""
    echo "      Example: ./rtr.sh -i ./rtr_inputs/rtr_ut.json"
    echo "      Example: ./rtr.sh -o /tmp/rtr -s /home/user/wazuh/src/engine -i ./rtr_inputs/rtr_ut.json -v -b no"
}

run() {
    echo "Running RTR on '$SRC_DIR'. Output directory: '$OUTPUT_DIR'. RTR input file: '$RTR_CONFIG'"
    jq -c '.steps[]' $RTR_CONFIG | while read step
    do
        STEP_DESC=`echo $step | jq -r '.description'`
        STEP_PARAMS=`echo $step | jq -r '.parameters | join(" ")'`
        echo "->Step: $STEP_DESC"
        docker run --rm -v $SRC_DIR:/source -v $OUTPUT_DIR:/output -v $RTR_DIR:/rtr $CONTAINER_NAME /rtr/rtr.py $VERBOSE -u $USERID -g $GROUPID -o /output -s /source $STEP_PARAMS
        docker_exit_code=$?
        if [ $docker_exit_code -ne 0 ]; then
            echo "Execution fail, RTR step: $STEP_DESC."
            return $docker_exit_code
        fi
    done
}

while getopts ":ho:s:i::vb:" option
do
    case "${option}" in
        h) # display Help
            Help
            exit;;
        o) # output directory
            OUTPUT_DIR=${OPTARG};;
        s) # source directory
            SRC_DIR=${OPTARG};;
        i) # rtr input file
            RTR_CONFIG=${OPTARG};;
        v) # verbose
            VERBOSE='-v';;
        b) # build docker
            BUILD_DOCKER=${OPTARG};;
        :) # missing argument
            echo "Error: Missing argument for option '$OPTARG'."
            exit;;
        \?) # Invalid option
            echo "Error: Invalid option."
            exit;;
    esac
done

if [[ "$BUILD_DOCKER" == "yes" ]]; then
    build
fi

run
if [ $? -ne 0 ]; then
    echo "RTR failed. Results on $OUTPUT_DIR directory."
    exit 1
else
    echo "RTR was succesfull. Results on $OUTPUT_DIR directory."
    exit 0
fi
