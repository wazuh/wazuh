#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains tools for processing events from a Google Cloud subscription."""  # noqa: E501

import json
import logging
import socket

from google.api_core import exceptions as google_exceptions
from google.cloud import pubsub_v1 as pubsub

import tools

logger = logging.getLogger(tools.logger_name)


class WazuhGCloudSubscriber:
    """Class for sending events from Google Cloud to Wazuh."""

    header = '1:Wazuh-GCloud:'

    def __init__(self, credentials_file: str, project: str,
                 subscription_id: str):
        """Instantiate a WazuhGCloudSubscriber object.

        :params credentials_file: Path to credentials file
        :params project: Project name
        :params subscription_id: Subscription ID
        """
        # get Wazuh paths
        self.wazuh_path, self.wazuh_version, self.wazuh_queue = tools.get_wazuh_paths()  # noqa: E501
        # get subscriber
        self.subscriber = self.get_subscriber_client(credentials_file).api
        self.subscription_path = self.get_subscription_path(project,
                                                            subscription_id)

    def get_subscriber_client(self, credentials_file: str) \
            -> pubsub.subscriber.Client:
        """Get a subscriber client.

        :param credentials_file: Path to credentials file
        :return: Instance of subscriber client object created with the
            provided key
        """
        return pubsub.subscriber.Client.from_service_account_file(credentials_file)  # noqa: E501

    def get_subscription_path(self, project: str, subscription_id: str) \
            -> str:
        """Get the subscription path.

        :param project: Project name
        :param subscription_id: Subscription ID
        :return: String with the subscription path
        """
        return self.subscriber.subscription_path(project, subscription_id)

    def send_msg(self, msg: bytes):
        """Send an event to the Wazuh queue.

        :param msg: Event to be sent
        """
        event_json = f'{self.header}{self.format_msg(msg)}'.encode(errors='replace')  # noqa: E501
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            s.send(event_json)
            s.close()
        except socket.error as e:
            if e.errno == 111:
                logger.critical('Wazuh must be running')
                raise e
            else:
                logger.critical('Error sending event to Wazuh')
                raise e

    def format_msg(self, msg: bytes) -> str:
        """Format a message.

        :param msg: Message to be formatted
        """
        return msg.decode(errors='replace')

    def process_message(self, ack_id: str, data: bytes):
        """Send a message to Wazuh queue.

        :param ack_id: ACK_ID from event
        :param data: Data to be sent to Wazuh
        """
        self.send_msg(data)
        self.subscriber.acknowledge(self.subscription_path, [ack_id])

    def check_permissions(self):
        """Check if permissions are OK for executing the wodle."""
        required_permissions = {'pubsub.subscriptions.consume'}
        response = self.subscriber.test_iam_permissions(self.subscription_path,
                                                        required_permissions)
        if required_permissions.difference(response.permissions) != set():
            error_message = 'ERROR: No permissions for executing the ' \
                'wodle from this subscription'
            raise Exception(error_message)

    def pull_request(self, max_messages: int = 100) \
            -> pubsub.types.PullResponse:
        """Make request for pulling messages from the subscription.

        :param max_messages: Maximum number of messages to retrieve
        :return: Response of pull request. If the deadline is exceeded,
            the method will return an empty PullResponse object
        """
        try:
            response = self.subscriber.pull(self.subscription_path,
                                            max_messages=max_messages,
                                            return_immediately=True)
        except google_exceptions.DeadlineExceeded:
            logger.warning('Deadline exceeded when pulling messages. '
                           'No more messages will be retrieved on this '
                           'execution')
            response = pubsub.types.PullResponse()

        return response

    def process_messages(self, max_messages: int = 100) -> int:
        """Process the available messages in the subscription.

        :param max_messages: Maximum number of messages to retrieve
        :return: Number of processed messages
        """
        processed_messages = 0
        response = self.pull_request(max_messages)
        while len(response.received_messages) > 0:
            for message in response.received_messages:
                message_data: bytes = message.message.data
                logger.debug(f'Processing event:\n{message_data.decode()}')
                self.process_message(message.ack_id, message_data)
                processed_messages += 1  # increment processed_messages counter
            # get more messages
            response = self.pull_request(max_messages)

        return processed_messages
