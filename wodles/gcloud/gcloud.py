#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from a Google Cloud subscription."""
import os
from concurrent.futures import ThreadPoolExecutor

import tools
from integration import WazuhGCloudSubscriber

try:
    max_threads = os.cpu_count() * 5
except TypeError:
    max_threads = 5

try:
    # get script arguments
    arguments = tools.get_script_arguments()
    project = arguments.project
    subscription_id = arguments.subscription_id
    credentials_file = arguments.credentials_file
    max_messages = arguments.max_messages
    log_level = arguments.log_level
    n_threads = arguments.n_threads

    # get logger
    logger = tools.get_stdout_logger(tools.logger_name, log_level)

    if n_threads > max_threads:
        n_threads = max_threads
        logger.warning(f'Reached maximum number of threads. Truncating to {max_threads}')

    logger.debug(f"Setting {n_threads} thread{'s' if n_threads > 1 else ''} to pull {max_messages}" 
                 f" message{'s' if max_messages > 1 else ''} each")

    # process messages
    with ThreadPoolExecutor() as executor:
        futures = []

        # check permissions
        subscriber_client = WazuhGCloudSubscriber(credentials_file, project, subscription_id)
        subscriber_client.check_permissions()
        futures.append(executor.submit(subscriber_client.process_messages, max_messages // n_threads))

        for _ in range(n_threads - 1):
            client = WazuhGCloudSubscriber(credentials_file, project, subscription_id)
            futures.append(executor.submit(client.process_messages, max_messages // n_threads))

    num_processed_messages = sum([future.result() for future in futures])

except Exception as e:
    # write the trace in the log file
    logger.critical('An exception happened while running the wodle:\n',
                    exc_info=e)

else:
    logger.info(f'Received and acknowledged {num_processed_messages} messages')  # noqa: E501

os._exit(0)
