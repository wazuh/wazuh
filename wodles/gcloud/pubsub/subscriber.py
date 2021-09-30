#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import sys
import socket
from os.path import abspath, dirname
import google.api_core.exceptions

sys.path.insert(0, dirname(dirname(abspath(__file__))))
import utils


try:
    from google.cloud import pubsub_v1 as pubsub
except ImportError:
    raise Exception('ERROR: google-cloud-storage module is required.')


class WazuhGCloudSubscriber:
    """Class for sending events from Google Cloud to Wazuh."""

    header = '1:Wazuh-GCloud:'
    key_name = 'gcp'

    def __init__(self, credentials_file: str, project: str, logger, subscription_id: str, max_messages: int = 100):
        """Instantiate a WazuhGCloudSubscriber object.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file
        project : str
            Project name
        subscription_id : str
            Subscription ID
        max_messages : int
            Maximum number of messages to retrieve
        """
        self.logger = logger

        # get Wazuh paths
        self.wazuh_path = utils.find_wazuh_path()
        self.wazuh_version = utils.get_wazuh_version()
        # get subscriber
        self.subscriber = self.get_subscriber_client(credentials_file)
        self.subscription_path = self.get_subscription_path(project, subscription_id)
        # Analysisd queue
        self.wazuh_queue = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    @staticmethod
    def get_subscriber_client(credentials_file: str) -> pubsub.subscriber.Client:
        """Get a subscriber client.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file

        Returns
        -------
        Instance of subscriber client object created with the provided key
        """
        return pubsub.subscriber.Client.from_service_account_file(credentials_file)  # noqa: E501

    def get_subscription_path(self, project: str, subscription_id: str) -> str:
        """Get the subscription path.

        Parameters
        ----------
        project : str
            Project name
        subscription_id : str
            Subscription ID

        Returns
        -------
        String with the subscription path
        """
        return self.subscriber.subscription_path(project, subscription_id)

    def check_permissions(self):
        """Check if permissions are OK for executing the wodle."""
        required_permissions = {'pubsub.subscriptions.consume'}
        response = self.subscriber.test_iam_permissions(request={'resource': self.subscription_path,
                                                                 'permissions': required_permissions})
        if required_permissions.difference(response.permissions) != set():
            error_message = 'ERROR: No permissions for executing the wodle from this subscription'
            raise Exception(error_message)

    def format_msg(self, msg: bytes) -> str:
        """Format a message.
        :param msg: Message to be formatted
        """
        # Insert msg as value of self.key_name key.
        return f'{{"integration": "gcp", "{self.key_name}": {msg.decode(errors="replace")}}}'

    def send_message(self, message):
        """Send a message with a header to the analysisd queue.
        :param message: Message to send to the analysisd queue
        """
        self.wazuh_queue.send(f'{self.header}{message}'.encode(errors='replace'))

    def pull_request(self, max_messages) -> int:
        """Make request for pulling messages from the subscription and acknowledge them.
        :param max_messages: Maximum number of messages to retrieve
        :return: Number of processed messages
        """
        try:
            response = self.subscriber.pull(
                request={'subscription': self.subscription_path,
                         'max_messages': max_messages}
            )
        except google.api_core.exceptions.DeadlineExceeded:
            self.logger.warning('Deadline exceeded when pulling messages. No more messages will be retrieved on this '
                                'execution')
            return 0

        ack_ids = []
        for received_message in response.received_messages:
            formatted_message = self.format_msg(received_message.message.data)
            self.logger.debug(f'Processing event: {formatted_message}')
            ack_ids.append(received_message.ack_id)
            self.send_message(formatted_message)

        ack_ids and self.subscriber.acknowledge(
            request={'subscription': self.subscription_path, 'ack_ids': ack_ids}
        )

        return len(response.received_messages)

    def process_messages(self, max_messages: int = 100) -> int:
        """Process the available messages in the subscription.
        :param max_messages: Maximum number of messages to retrieve
        :return: Number of processed messages
        """
        try:
            self.wazuh_queue.connect(utils.ANALYSISD)
            with self.subscriber:
                processed_messages = 0
                pulled_messages = self.pull_request(max_messages)
                while pulled_messages > 0 and processed_messages < max_messages:
                    processed_messages += pulled_messages
                    # get more messages
                    if processed_messages < max_messages:
                        pulled_messages = self.pull_request(max_messages - processed_messages)
                return processed_messages
        except socket.error as e:
            if e.errno == 111:
                self.logger.critical('Wazuh must be running')
                raise e
            else:
                self.logger.critical('Error sending event to Wazuh')
                raise e
        finally:
            self.wazuh_queue.close()
