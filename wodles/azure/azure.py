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
import logging
import sys
from os.path import abspath, dirname

import wodles.azure.db.orm as orm
from wodles.azure.azure_utils import get_script_arguments, set_logger
from wodles.azure.services.analytics import start_log_analytics
from wodles.azure.services.graph import start_graph
from wodles.azure.services.storage import start_storage

sys.path.insert(0, dirname(dirname(abspath(__file__))))


if __name__ == "__main__":
    args = get_script_arguments()
    set_logger(args.debug_level)

    if not orm.check_database_integrity():
        sys.exit(1)

    if args.log_analytics:
        start_log_analytics(args)
    elif args.graph:
        start_graph(args)
    elif args.storage:
        start_storage(args)
    else:
        logging.error(
            "No valid API was specified. Please use 'graph', 'log_analytics' or 'storage'."
        )
        sys.exit(1)
