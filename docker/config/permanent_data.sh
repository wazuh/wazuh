#!/bin/bash
# Wazuh App Copyright (C) 2017, Wazuh Inc. (License GPLv2)

# Variables
source /permanent_data.env

WAZUH_INSTALL_PATH=/var/ossec
DATA_TMP_PATH=${WAZUH_INSTALL_PATH}/data_tmp
mkdir ${DATA_TMP_PATH}

# Move exclusion files to EXCLUSION_PATH
EXCLUSION_PATH=${DATA_TMP_PATH}/exclusion
mkdir ${EXCLUSION_PATH}

for exclusion_file in "${PERMANENT_DATA_EXCP[@]}"; do
  # Create the directory for the exclusion file if it does not exist
  DIR=$(dirname "${exclusion_file}")
  if [ ! -e ${EXCLUSION_PATH}/${DIR}  ]
  then
    mkdir -p ${EXCLUSION_PATH}/${DIR}
  fi

  mv ${exclusion_file} ${EXCLUSION_PATH}/${exclusion_file}
done

# Move permanent files to PERMANENT_PATH
PERMANENT_PATH=${DATA_TMP_PATH}/permanent
mkdir ${PERMANENT_PATH}

for permanent_dir in "${PERMANENT_DATA[@]}"; do
  # Create the directory for the permanent file if it does not exist
  DIR=$(dirname "${permanent_dir}")
  if [ ! -e ${PERMANENT_PATH}${DIR}  ]
  then
    mkdir -p ${PERMANENT_PATH}${DIR}
  fi
  
  mv ${permanent_dir} ${PERMANENT_PATH}${permanent_dir}

done
