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
logger = logging.getLogger(__name__)
core.set_logger(log_level)

# get subscriber client
subscriber = core.get_subscriber_client(credentials_file)
# get subscription path
subscription_path = core.get_subscription_path(subscriber, project_id,
                                               subscription_name)
# check permissions
if not core.check_permissions(subscriber, subscription_path):
    sys.exit('No permissions for executing the wodle from this subscription')

# pull messages
response = subscriber.pull(subscription_path, max_messages=max_messages,
                           return_immediately=True)  # consider to remove this parameter

processed_messages = 0  # counter for processed messages

# process messages until queue will be empty
while len(response.received_messages) > 0:
    for message in response.received_messages:
        logger.info(f'Sending message {message.message.data} to Wazuh')
        core.process_message(subscriber, subscription_path, message.ack_id,
                             message.message.data)
        processed_messages += 1  # increment processed_messages counter
        logger.info(f'ACK received from {message.message.data}')
    # get more messages
    response = subscriber.pull(subscription_path, max_messages=max_messages,
                               return_immediately=True)

logger.info(f'Received and acknowledged {processed_messages} messages. Done.')
print(f'Received and acknowledged {processed_messages} messages. Done.')
