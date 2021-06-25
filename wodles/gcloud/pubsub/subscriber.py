#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import os
import sys

try:
    from google.cloud import pubsub_v1 as pubsub
except ImportError:
    raise Exception('ERROR: google-cloud-storage module is required.')

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
from integration import WazuhGCloudIntegration


class WazuhGCloudSubscriber(WazuhGCloudIntegration):
    def __init__(self, credentials_file: str, logger, project: str, subscription_id: str, max_messages: int = 100):
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
        super().__init__(logger)

        self.subscriber = self.get_subscriber_client(credentials_file).api
        self.subscription_path = self.get_subscription_path(project, subscription_id)
        self.max_messages = max_messages

    def get_subscriber_client(self, credentials_file: str) -> pubsub.subscriber.Client:
        """Get a subscriber client.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file

        Returns
        -------
        Instance of subscriber client object created with the provided key
        """
        return pubsub.subscriber.Client.from_service_account_file(credentials_file)

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

    def process_message(self, ack_id: str, data: bytes):
        """Send a message to Wazuh queue.

        Parameters
        ----------
        ack_id : str
            ACK_ID from event
        data : str
            Data to be sent to Wazuh
        """
        formatted_msg = self.format_msg(data.decode(errors='replace'))
        self.send_msg(formatted_msg)
        self.subscriber.acknowledge(self.subscription_path, [ack_id])

    def check_permissions(self):
        """Check if permissions are OK for executing the wodle."""
        required_permissions = {'pubsub.subscriptions.consume'}
        response = self.subscriber.test_iam_permissions(self.subscription_path, required_permissions)
        if required_permissions.difference(response.permissions):
            error_message = 'ERROR: No permissions for executing the wodle from this subscription'
            raise Exception(error_message)

    def pull_request(self, max_messages: int = 100) -> pubsub.types.PullResponse:
        """Make request for pulling messages from the subscription.

        Parameters
        ----------
        max_messages : int
            Maximum number of messages to retrieve

        Returns
        -------
        Response of pull request. If the deadline is exceeded, the method will return an empty PullResponse object
        """
        try:
            response = self.subscriber.pull(self.subscription_path,
                                            max_messages=max_messages,
                                            return_immediately=True)
        except google_exceptions.DeadlineExceeded:
            self.logger.warning('Deadline exceeded when pulling messages. No more messages will be retrieved on this '
                                'execution')
            response = pubsub.types.PullResponse()

        return response

    def process_data(self) -> int:
        """Process the available messages in the subscription.

        Returns
        -------
        Number of processed messages
        """
        processed_messages = 0
        response = self.pull_request(self.max_messages)
        while len(response.received_messages) > 0 and processed_messages < self.max_messages:
            for message in response.received_messages:
                message_data: bytes = message.message.data
                self.logger.debug(f'Processing event:\n{self.format_msg(message_data.decode(errors="replace"))}')
                self.process_message(message.ack_id, message_data)
                processed_messages += 1
            # get more messages
            if processed_messages < self.max_messages:
                response = self.pull_request(self.max_messages - processed_messages)
        return processed_messages
