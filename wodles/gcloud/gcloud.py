#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from Google Cloud PubSub service and GCS Buckets."""

import tools
from sys import exit
from os import cpu_count
from buckets.access_logs import GCSAccessLogs
from pubsub.subscriber import WazuhGCloudSubscriber
from concurrent.futures import ThreadPoolExecutor

try:
    max_threads = cpu_count() * 5
except TypeError:
    max_threads = 5

try:
    # get script arguments
    arguments = tools.get_script_arguments()
    logger = tools.get_stdout_logger(tools.logger_name, arguments.log_level)
    credentials_file = arguments.credentials_file
    max_messages = arguments.max_messages
    log_level = arguments.log_level
    num_processed_messages = 0

    if arguments.integration_type == "pubsub":
        if arguments.subscription_id is None:
            raise Exception(f'A subscription ID is required. Use -s <SUBSCRIPTION ID> to specify it.')
        if arguments.project is None:
            raise Exception(f'A project ID is required. Use -p <PROJECT ID> to specify it.')

        project = arguments.project
        subscription_id = arguments.subscription_id
        max_messages = arguments.max_messages
        n_threads = arguments.n_threads

        if n_threads > max_threads:
            n_threads = max_threads
            logger.warning(f'Reached maximum number of threads. Truncating to {max_threads}.')
        if n_threads < tools.min_num_threads:
            logger.error(f'The minimum number of threads is {tools.min_num_threads}. Please check your configuration.')
            exit(1)
        if max_messages < tools.min_num_messages:
            logger.error(f'The minimum number of messages is {tools.min_num_messages}. Please check your configuration.')
            exit(1)

        logger.debug(f"Setting {n_threads} thread{'s' if n_threads > 1 else ''} to pull {max_messages}"
                     f" message{'s' if max_messages > 1 else ''} in total")

        # process messages
        with ThreadPoolExecutor() as executor:
            futures = []

            # check permissions
            subscriber_client = WazuhGCloudSubscriber(credentials_file, project, logger, subscription_id)
            subscriber_client.check_permissions()
            messages_per_thread = max_messages // n_threads
            remaining_messages = max_messages % n_threads
            futures.append(executor.submit(subscriber_client.process_messages, messages_per_thread + remaining_messages))

            if messages_per_thread > 0:
                for _ in range(n_threads - 1):
                    client = WazuhGCloudSubscriber(credentials_file, project, logger, subscription_id)
                    futures.append(executor.submit(client.process_messages, messages_per_thread))

        num_processed_messages = sum([future.result() for future in futures])

    elif arguments.integration_type == "access_logs":
        if arguments.n_threads != tools.min_num_threads:
            logger.error(f'The parameter -t/--num_threads only works with the Pub/Sub module.')
            exit(1)
        if arguments.bucket_name is None:
            raise Exception(f'The name of the bucket is required. Use -b <BUCKET_NAME> to specify it.')

        f_kwargs = {"bucket_name": arguments.bucket_name,
                    "prefix": arguments.prefix,
                    "delete_file": arguments.delete_file,
                    "only_logs_after": arguments.only_logs_after}
        integration = GCSAccessLogs(arguments.credentials_file, logger, **f_kwargs)
        integration.check_permissions()
        num_processed_messages = integration.process_data()

    else:
        raise Exception(f'Unsupported gcloud integration type: {arguments.integration_type}')


except Exception as e:
    logger.critical(f'An exception happened while running the wodle: {e}')
    exit(1)

else:
    logger.info(f'Received {"and acknowledged " if arguments.integration_type == "pubsub" else ""}'
                f'{num_processed_messages} message{"s" if num_processed_messages != 1 else ""}')
    exit(0)
