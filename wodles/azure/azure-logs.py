#!/usr/bin/env python3

###
# Integration of Wazuh agent with Microsoft Azure
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
###

################################################################################################
# pip install azure
# https://github.com/Azure/azure-sdk-for-python
# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
################################################################################################
import sys

from azure_utils import get_script_arguments
from db.orm import check_database_integrity
from azure_services.analytics import start_log_analytics
from azure_services.graph import start_graph
from azure_services.storage import start_storage

from shared.wazuh_cloud_logger import WazuhCloudLogger

# Set Azure logger
azure_logger = WazuhCloudLogger(
    logger_name=':azure_wodle:'
)

if __name__ == '__main__':
    args = get_script_arguments()

    # Get log level
    log_level = args.debug_level

    # Set log level
    azure_logger.set_level(
        log_level=log_level
    )

    if not check_database_integrity():
        sys.exit(1)

    if args.log_analytics:
        start_log_analytics(args)
    elif args.graph:
        start_graph(args)
    elif args.storage:
        start_storage(args)
    else:
        azure_logger.error("No valid API was specified. Please use 'graph', 'log_analytics' or 'storage'.")
        sys.exit(1)
