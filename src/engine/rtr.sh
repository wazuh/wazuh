#!/bin/bash

SRC_DIR=$(realpath $(dirname "$0"))
OUTPUT_DIR=$(realpath $(mktemp -d -t wazuh-rtr-XXXXXX))
CONTAINER_NAME=wazuh-rtr-engine
RTR_DIR=$SRC_DIR/.rtr
RTR_BIN=rtr.py
RTR_CONFIG="rtr_inputs/rtr_cicd.json"
CURRENT_UID_GID=$(id -u -n):$(id -g -n)
PERMISSIONS_BACKUP_FILE=/tmp/permissions.acl
USERNAME=$(logname)
USERID=$(id -u $USERNAME)
GROUPID=$(id -g $USERNAME)
VERBOSE=''
BUILD_DOCKER="yes"
THREADS=""
PARALLEL="no"

build() {

    if [[ "$VERBOSE" = "-v" ]]; then
        docker build -f .rtr/Dockerfile -t $CONTAINER_NAME .
    else
        docker build -f .rtr/Dockerfile -t $CONTAINER_NAME -q . > /dev/null
    fi
}

Help() {
    # Display Help
    echo "Run RTR on a directory within a Docker container."
    echo
    echo "Syntax: rtr.sh [-h|o|s|i|v|b]"
    echo "Options:"
    echo "h     Prints this help message."
    echo "o     Output directory. It creates a temporary directory in '/tmp/wazuh-rtr-XXXXXX' if not specified."
    echo "s     Source directory. It uses the directory of this script if not specified."
    echo "i     RTR input file. By default, it uses 'rtr_inputs/rtr_cicd.json'."
    echo "v     Verbose. Enables debug mode for RTR."
    echo "b     Build docker. By default, it builds the docker image. Set to 'no' to skip the build."
    echo "t     Threads. Sets the number of threads for all the steps, overwriting the value of the json configuration files."
    echo "p     Parallel. Runs all the steps in parallel. The output directory will contain a folder for each step. The input file will be ignored."
    echo
    echo "      Examples:"
    echo "      Run all the steps in single mode with default params "
    echo "          ./rtr.sh"
    echo "      Run a single step with all default parameters in single mode "
    echo "          ./rtr.sh -i ./rtr_inputs/rtr_ut.json"
    echo "      Run a single step in a fixed folder forcing 8 threads and not building the docker image with verbose output: "
    echo "          ./rtr.sh -o /tmp/rtr -s /home/user/wazuh/src/engine -i ./rtr_inputs/rtr_ut.json -v -b no -t 8"
    echo "      Run all steps in parallel mode forcing 8 threads in a fixed folder: "
    echo "          ./rtr.sh -o /tmp/rtr -s /home/user/wazuh/src/engine -p -t 8"
}

run() {
    LOCAL_SRC_DIR=$1
    LOCAL_OUTPUT_DIR=$2
    LOCAL_RTR_CONFIG=$3
    echo "Running RTR on '$LOCAL_SRC_DIR'. Output directory: '$LOCAL_OUTPUT_DIR'. RTR input file: '$LOCAL_RTR_CONFIG'"
    jq -c '.steps[]' $LOCAL_RTR_CONFIG | while read step
    do
        STEP_DESC=$(echo $step | jq -r '.description')
        STEP_PARAMS=$(echo $step | jq -r '.parameters | join(" ")')
        echo "->Step: '$STEP_DESC'"
        STEP_DESC_TRIM=$(echo "${STEP_DESC// /-}" | tr '[:upper:]' '[:lower:]')
        STEP_DESC_TRIM=$(echo "${STEP_DESC_TRIM//\(/-}")
        STEP_DESC_TRIM=$(echo "${STEP_DESC_TRIM//\)/-}")
        RANDOM_VALUE=$RANDOM
        docker run --rm --name $STEP_DESC_TRIM-$RANDOM_VALUE --hostname $STEP_DESC_TRIM-$RANDOM_VALUE -v $LOCAL_SRC_DIR:/source -v $LOCAL_OUTPUT_DIR:/output -v $RTR_DIR:/rtr $CONTAINER_NAME /rtr/rtr.py $VERBOSE -u $USERID -g $GROUPID -o /output -s /source $STEP_PARAMS $THREADS
        docker_exit_code=$?
        if [ $docker_exit_code -ne 0 ]; then
            echo "Execution fail for '$LOCAL_RTR_CONFIG', RTR step: '$STEP_DESC'."
            return $docker_exit_code
        fi
    done
}

while getopts ":ho:s:i::vb:t::p" option
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
        t) # threads
            THREADS="--threads "${OPTARG};;
        p) # parallel
            PARALLEL="yes";;
        :) # missing argument
            echo "Error: Missing argument for option '$OPTARG'."
            Help
            exit;;
        \?) # Invalid option
            echo "Error: Invalid option."
            Help
            exit;;
    esac
done

if [[ "$BUILD_DOCKER" == "yes" ]]; then
    build
fi

if [[ "$PARALLEL" == "no" ]]; then
    echo "Running RTR in single mode."
    run $SRC_DIR $OUTPUT_DIR $RTR_CONFIG
    if [ $? -ne 0 ]; then
        echo "RTR failed. Results on $OUTPUT_DIR directory."
        exit 1
    else
        echo "RTR was succesfull. Results on $OUTPUT_DIR directory."
        exit 0
    fi
else
    echo "Running RTR in parallel mode."
    PARALLEL_STEPS=$( jq -cr '.steps | join(" ")' $SRC_DIR/rtr_inputs/rtr_parallel.json )
    PIDS_ARRAY=()
    FINAL_EXIT_CODE=0

    for step in ${PARALLEL_STEPS[@]}; do
        echo "Launching RTR step: '$step'"
        FOLDER_SUFFIX=${step%.*}
        run $SRC_DIR "$OUTPUT_DIR/$FOLDER_SUFFIX" "$SRC_DIR/rtr_inputs/$step" &
        PIDS_ARRAY+=( $! )
    done

    i=0
    for step in ${PARALLEL_STEPS[@]}; do
        echo "Waiting for RTR step: $step. PID: ${PIDS_ARRAY[$i]}"
        wait ${PIDS_ARRAY[$i]} || let "FINAL_EXIT_CODE=1"
        i=$((i+1))
    done

    if [ $FINAL_EXIT_CODE -ne 0 ]; then
        echo "RTR failed. Results on $OUTPUT_DIR directory."
        exit 1
    else
        echo "RTR was succesfull. Results on $OUTPUT_DIR directory."
        exit 0
    fi
fi
