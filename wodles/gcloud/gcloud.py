#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from Google Cloud PubSub service and GCS Buckets."""

import tools
import exceptions
from sys import exit
from os import cpu_count
from buckets.access_logs import GCSAccessLogs
from pubsub.subscriber import WazuhGCloudSubscriber
from concurrent.futures import ThreadPoolExecutor


def main():
    logger = tools.get_stdout_logger(tools.logger_name)

    try:
        # get script arguments
        arguments = tools.get_script_arguments()
        logger.setLevel(arguments.log_level)
        credentials_file = arguments.credentials_file
        log_level = arguments.log_level
        num_processed_messages = 0

        if arguments.integration_type == "pubsub":
            logger.info("Working with Google Cloud Pub/Sub")
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
                logger.warning(f'Reached maximum number of threads. Truncating to {max_threads}.')
            if n_threads < tools.min_num_threads:
                raise exceptions.GCloudError(1202)
            if max_messages < tools.min_num_messages:
                raise exceptions.GCloudError(1203)

            logger.debug(f"Setting {n_threads} thread{'s' if n_threads > 1 else ''} to pull {max_messages}"
                         f" message{'s' if max_messages > 1 else ''} in total")

            # process messages
            with ThreadPoolExecutor() as executor:
                futures = []

                # check permissions
                subscriber_client = WazuhGCloudSubscriber(credentials_file, project, logger, subscription_id)
                logger.debug("Checking credentials")
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
            logger.info("Working with Google Cloud Access Logs")
            if not arguments.bucket_name:
                raise exceptions.GCloudError(1103)

            f_kwargs = {"bucket_name": arguments.bucket_name,
                        "prefix": arguments.prefix,
                        "delete_file": arguments.delete_file,
                        "only_logs_after": arguments.only_logs_after,
                        "reparse": arguments.reparse}
            integration = GCSAccessLogs(arguments.credentials_file, logger, **f_kwargs)
            logger.debug("Checking credentials")
            integration.check_permissions()
            num_processed_messages = integration.process_data()

        else:
            raise exceptions.GCloudError(1002, integration_type=arguments.integration_type)

    except exceptions.WazuhIntegrationException as gcloud_exception:
        logging_func = logger.critical if \
            isinstance(gcloud_exception, exceptions.WazuhIntegrationInternalError) else \
            logger.error

        logging_func(f'An exception happened while running the wodle: {gcloud_exception}', exc_info=log_level == 1)
        exit(gcloud_exception.errcode)

    except Exception as e:
        logger.critical(f'Unknown error: {e}', exc_info=True)
        exit(exceptions.UNKNOWN_ERROR_ERRCODE)

    else:
        logger.info(f'Received {"and acknowledged " if arguments.integration_type == "pubsub" else ""}'
                    f'{num_processed_messages} message{"s" if num_processed_messages != 1 else ""}')
        exit(0)


if __name__ == "__main__":
    main()
