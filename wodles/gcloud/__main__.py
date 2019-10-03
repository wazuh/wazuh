#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from a Google Cloud subscription."""

import core
import logging
import sys


# get script arguments
arguments = core.get_script_arguments()
project_id = arguments.project_id
subscription_name = arguments.subscription_name
credentials_file = arguments.credentials_file
max_messages = arguments.max_messages
log_level = arguments.log_level

# set logger
logger = logging.getLogger()
core.set_logger(log_level)

# get Google Cloud client
client = core.GCloudClient(credentials_file, project_id, subscription_name)

# check permissions about subscription
if not client.check_permissions():
    logger.critical('No permissions for executing the wodle from this subscription')  # noqa: E501
    sys.exit('No permissions for executing the wodle from this subscription')

# process messages
num_processed_messages = client.process_messages(max_messages)

logger.info(f'Received and acknowledged {num_processed_messages} messages')  # noqa: E501
print(f'Received and acknowledged {num_processed_messages} messages')
