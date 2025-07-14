#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2
import logging
from os.path import abspath, dirname
from sys import path
from json import JSONDecodeError

path.insert(0, dirname(dirname(dirname(abspath(__file__)))))
import exceptions
from integration import WazuhGCloudIntegration


try:
    from google.cloud import pubsub_v1 as pubsub
    import google.api_core.exceptions
except ImportError as e:
    raise exceptions.GCloudError(errcode=1003, package=e.name)


class WazuhGCloudSubscriber(WazuhGCloudIntegration):
    """Class for sending events from Google Cloud to Wazuh."""

    def __init__(self, credentials_file: str, project: str, logger: logging.Logger, subscription_id: str):
        """Instantiate a WazuhGCloudSubscriber object.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file.
        project : str
            Project name.
        subscription_id : str
            Subscription ID.
        logger: logging.Logger
            The logger that will be used to send messages to stdout.

        Raises
        ------
        exceptions.GCloudError
            If the credentials file doesn't exist or have a wrong structure.
        """
        super().__init__(logger)

        # get subscriber
        try:
            self.subscriber = self.get_subscriber_client(credentials_file)
            self.subscription_path = self.get_subscription_path(project, subscription_id)
        except JSONDecodeError as error:
            raise exceptions.GCloudError(1000, credentials_file=credentials_file) from error
        except FileNotFoundError as error:
            raise exceptions.GCloudError(1001, credentials_file=credentials_file) from error

    @staticmethod
    def get_subscriber_client(credentials_file: str) -> pubsub.subscriber.Client:
        """Get a subscriber client.

        Parameters
        ----------
        credentials_file : str, optional
            Path to credentials file. If not provided, the client will attempt
            to use Application Default Credentials or other environment
            configurations.

        Returns
        -------
        pubsub.subscriber.Client
            Instance of subscriber client object.
        """
        if credentials_file:
            # If a credentials file path is provided, use it to create the client.
            return pubsub.subscriber.Client.from_service_account_file(credentials_file)
        else:
            # If no credentials file is provided, instantiate the client directly.
            # This will attempt to use Application Default Credentials (ADC).
            return pubsub.subscriber.Client()

    def get_subscription_path(self, project: str, subscription_id: str) -> str:
        """Get the subscription path.

        Parameters
        ----------
        project : str
            Project name.
        subscription_id : str
            Subscription ID.

        Returns
        -------
        str
            String with the subscription path.
        """
        return self.subscriber.subscription_path(project, subscription_id)

    def check_permissions(self):
        """
        Check if permissions are OK for executing the wodle.

        Raises
        ------
        exceptions.GCloudError
            If the parameters or credentials are invalid.
        """
        required_permissions = {'pubsub.subscriptions.consume'}
        try:
            response = self.subscriber.test_iam_permissions(
                request={'resource': self.subscription_path,
                         'permissions': required_permissions})

        except google.api_core.exceptions.NotFound as e:
            if 'project not found or user does not have access' in e.message:
                raise exceptions.GCloudError(1205, project=self.subscription_path.split('/')[1])
            else:
                raise exceptions.GCloudError(1204, subscription=self.subscription_path.split('/')[-1])

        if required_permissions.difference(response.permissions) != set():
            raise exceptions.GCloudError(1206, permissions=required_permissions.difference(response.permissions))

    def pull_request(self, max_messages: int) -> int:
        """Make request for pulling messages from the subscription and acknowledge them.

        Parameters
        ----------
        max_messages: int
            Maximum number of messages to retrieve.

        Returns
        -------
        int
            Number of messages received and acknowledged.
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
            formatted_message = self.format_msg(received_message.message.data.decode(errors='replace'))
            self.logger.debug(f'Processing event: {formatted_message}')
            ack_ids.append(received_message.ack_id)
            self.send_msg(formatted_message)

        ack_ids and self.subscriber.acknowledge(
            request={'subscription': self.subscription_path, 'ack_ids': ack_ids}
        )

        return len(response.received_messages)

    def process_messages(self, max_messages: int = 100) -> int:
        """Process the available messages in the subscription.

        Parameters
        ----------
        max_messages: int
            Maximum number of messages to retrieve.

        Returns
        -------
        int
            Number of messages processed.
        """
        with self.subscriber, self.initialize_socket():
            processed_messages = 0
            pulled_messages = self.pull_request(max_messages)
            while pulled_messages > 0 and processed_messages < max_messages:
                processed_messages += pulled_messages
                # get more messages
                if processed_messages < max_messages:
                    pulled_messages = self.pull_request(max_messages - processed_messages)
        return processed_messages
