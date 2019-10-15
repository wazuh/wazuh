#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from a Google Cloud subscription."""

import tools
from integration import WazuhGCloudSubscriber

try:
    # get script arguments
    arguments = tools.get_script_arguments()
    project = arguments.project
    subscription_id = arguments.subscription_id
    credentials_file = arguments.credentials_file
    max_messages = arguments.max_messages
    log_level = arguments.log_level

    # get logger
    logger = tools.get_logger(tools.logger_name, log_level)

    # get Google Cloud client
    client = WazuhGCloudSubscriber(credentials_file, project, subscription_id)

    # check permissions about subscription
    client.check_permissions()

    # process messages
    num_processed_messages = client.process_messages(max_messages)

except Exception as e:
    # only show the trace in the logger if a parameter is set for doing that
    logger.critical('An exception happened while running the wodle:\n',
                    exc_info=e)
    raise e

else:
    logger.info(f'Received and acknowledged {num_processed_messages} messages')  # noqa: E501
