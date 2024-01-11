#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# All rights reserved.
# Wazuh.com

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Function: isConfigPresent
# Description: Function that checks if a 'configuration' is present in the 'ossec.conf' file.
# Parameters:
#   $1: Path to the ossec.conf file.
#   $2: Configuration pattern.
isConfigPresent()
{
    local OSSEC_CONF_PATH="$1"
    local CONFIG_PATTERN="$2"

    if ( grep -q "$CONFIG_PATTERN" "$OSSEC_CONF_PATH" ); then
        return 0
    fi

    return 1
}

# Function: updateIndexerTemplate
# Description: Function that appends the 'Indexer' template to the 'ossec.conf' file if it does not exist.
# Parameters:
#   $1: Path to the ossec.conf file.
#   $2: Path to the Indexer template file.
updateIndexerTemplate()
{
    local OSSEC_CONF_PATH="$1"
    local INDEXER_TEMPLATE_PATH="$2"

    if ! isConfigPresent "$OSSEC_CONF_PATH" "<indexer>"; then
        # Open config.
        printf "\n<ossec_config>\n\n" >> $OSSEC_CONF_PATH

        # Append 'Indexer' template.
        cat ${INDEXER_TEMPLATE_PATH} >> $OSSEC_CONF_PATH
        printf "\n" >> $OSSEC_CONF_PATH

        # Close config.
        printf "</ossec_config>\n" >> $OSSEC_CONF_PATH
    fi
}
