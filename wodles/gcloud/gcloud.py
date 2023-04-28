#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from Google Cloud PubSub service and GCS Buckets."""

import exceptions
import logging
from os import cpu_count
from sys import path, exit
from os.path import join, dirname, realpath

path.append(join(dirname(realpath(__file__)), '..', '..'))

# Local Imports
from buckets.access_logs import GCSAccessLogs
from pubsub.subscriber import WazuhGCloudSubscriber
from concurrent.futures import ThreadPoolExecutor
from wodles.shared.wazuh_cloud_logger import WazuhCloudLogger
from tools import MIN_NUM_THREADS, MIN_NUM_MESSAGES, get_script_arguments
from gcp_logger import GCPLogStrategy

# Set GCP logger
gcp_logger = WazuhCloudLogger(
        strategy=GCPLogStrategy()
)


def main():

    try:
        # Get script arguments
        arguments = get_script_arguments()

        # Get logger level
        log_lvl = arguments.log_level

        gcp_logger.set_level(log_level=log_lvl)

        # Get credentials file
        credentials_file = arguments.credentials_file

        if arguments.integration_type == "pubsub":
            if arguments.subscription_id is None:
                raise exceptions.GCloudError(1200)
            if arguments.project is None:
                raise exceptions.GCloudError(1201)

            project = arguments.project
            subscription_id = arguments.subscription_id
            max_messages = arguments.max_messages
            n_threads = arguments.n_threads

            try:
                max_threads = cpu_count() * 5
            except TypeError:
                max_threads = 5

            if n_threads > max_threads:
                n_threads = max_threads
                gcp_logger.warning(f'Reached maximum number of threads. Truncating to {max_threads}.')
            if n_threads < MIN_NUM_THREADS:
                raise exceptions.GCloudError(1202)
            if max_messages < MIN_NUM_MESSAGES:
                raise exceptions.GCloudError(1203)

            gcp_logger.debug(f"Setting {n_threads} thread{'s' if n_threads > 1 else ''} to pull {max_messages}"
                             f" message{'s' if max_messages > 1 else ''} in total")

            # process messages
            with ThreadPoolExecutor() as executor:
                futures = []

                # check permissions
                subscriber_client = WazuhGCloudSubscriber(credentials_file, project, gcp_logger, subscription_id)
                subscriber_client.check_permissions()
                messages_per_thread = max_messages // n_threads
                remaining_messages = max_messages % n_threads
                futures.append(
                    executor.submit(subscriber_client.process_messages, messages_per_thread + remaining_messages))

                if messages_per_thread > 0:
                    for _ in range(n_threads - 1):
                        client = WazuhGCloudSubscriber(credentials_file, project, gcp_logger, subscription_id)
                        futures.append(executor.submit(client.process_messages, messages_per_thread))

            num_processed_messages = sum([future.result() for future in futures])

        elif arguments.integration_type == "access_logs":
            if not arguments.bucket_name:
                raise exceptions.GCloudError(1103)

            f_kwargs = {"bucket_name": arguments.bucket_name,
                        "prefix": arguments.prefix,
                        "delete_file": arguments.delete_file,
                        "only_logs_after": arguments.only_logs_after,
                        "reparse": arguments.reparse}
            integration = GCSAccessLogs(arguments.credentials_file, gcp_logger, **f_kwargs)
            integration.check_permissions()
            num_processed_messages = integration.process_data()

        else:
            raise exceptions.GCloudError(1002, integration_type=arguments.integration_type)

    except exceptions.WazuhIntegrationException as gcloud_exception:
        logging_func = gcp_logger.critical if \
            isinstance(gcloud_exception, exceptions.WazuhIntegrationInternalError) else \
            gcp_logger.error

        logging_func(f'An exception happened while running the wodle: {gcloud_exception}')
        exit(gcloud_exception.errcode)

    except Exception as e:
        gcp_logger.critical(f'Unknown error: {e}')
        exit(exceptions.UNKNOWN_ERROR_ERRCODE)

    else:
        gcp_logger.info(f'Received {"and acknowledged " if arguments.integration_type == "pubsub" else ""}'
                        f'{num_processed_messages} message{"s" if num_processed_messages != 1 else ""}')
        exit(0)


if __name__ == "__main__":
    main()
