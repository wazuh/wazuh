#!/var/ossec/framework/python/bin/python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module processes events from Google Cloud PubSub service and GCS Buckets."""

import sys

import tools
from buckets.access_logs import GCSAccessLogs
from pubsub.subscriber import WazuhGCloudSubscriber


try:
    # get script arguments
    arguments = tools.get_script_arguments()

    logger = tools.get_stdout_logger(tools.logger_name, arguments.log_level)

    if arguments.integration_type == "pubsub":
        if arguments.subscription_id is None:
            raise Exception(f'A subscription ID is required. Use -s <SUBSCRIPTION ID> to specify it.')
        if arguments.project is None:
            raise Exception(f'A project ID is required. Use -p <PROJECT ID> to specify it.')

        f_kwargs = {"project": arguments.project,
                    "subscription_id": arguments.subscription_id,
                    "max_messages": arguments.max_messages}
        integration_type = WazuhGCloudSubscriber

    elif arguments.integration_type == "access_logs":
        if arguments.bucket_name is None:
            raise Exception(f'The name of the bucket is required. Use -b <BUCKET_NAME> to specify it.')

        f_kwargs = {"bucket_name": arguments.bucket_name,
                    "prefix": arguments.prefix,
                    "delete_file": arguments.delete_file,
                    "only_logs_after": arguments.only_logs_after}
        integration_type = GCSAccessLogs

    else:
        raise Exception(f'Unsupported gcloud integration type: {arguments.integration_type}')

    integration = integration_type(arguments.credentials_file, logger, **f_kwargs)
    integration.check_permissions()
    num_processed_messages = integration.process_data()

except Exception as e:
    logger.critical(f'An exception happened while running the wodle: {e}')
    sys.exit(1)

else:
    logger.info(f'Received and acknowledged {num_processed_messages} messages')
    sys.exit(0)
