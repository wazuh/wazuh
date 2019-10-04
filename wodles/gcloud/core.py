#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains tools for processing events from a Google Cloud subscription."""  # noqa: E501

import argparse
import datetime
import json
import logging
import os
import re
import socket

from google.api_core import exceptions as google_exceptions
from google.cloud import pubsub_v1 as pubsub


class GCloudClient:
    """Create a GCloudSubscriber object."""

    header = '1:Wazuh-GCloud:'

    def __init__(self, credentials_file: str, project_id: str,
                 subscription_name: str):
        """Instantiate a GCloudSubscriber object.

        :params credentials_file: Path to credentials file
        :params subscription_id: Project ID
        :params subscription_name: Subscription name
        """
        # get Wazuh paths
        self.wazuh_path, self.wazuh_version, self.wazuh_queue = self.get_wazuh_paths()  # noqa: E501
        # get subscriber
        self.subscriber = self.get_subscriber_client(credentials_file).api
        self.subscription_path = self.get_subscription_path(project_id,
                                                            subscription_name)

    def get_wazuh_paths(self) -> tuple:
        """Get Wazuh paths from ossec-init file."""
        re_path = re.compile(r'^([DIRECTORY]+)={1}"{1}([\w\/.]+)"{1}$')
        re_version = re.compile(r'^([VERSION]+)={1}"{1}([\w\/.]+)"{1}$')
        try:
            with open('/etc/ossec-init.conf') as f:
                lines = f.readlines()
                for line in lines:
                    path = re.search(re_path, line)
                    version = re.search(re_version, line)
                    if path:
                        wazuh_path = path.group(2)
                        continue
                    if version:
                        wazuh_version = version.group(2)
        except FileNotFoundError as e:
            logging.critical('ERROR: Wazuh installation not found')
            raise e

        if not (wazuh_path and wazuh_version):
            error_message = "ERROR: Error reading '/etc/ossec-init.conf' " \
                "file. Wodle cannot start"
            raise Exception(error_message)

        wazuh_queue = os.path.join(wazuh_path, 'queue', 'ossec', 'queue')

        return wazuh_path, wazuh_version, wazuh_queue

    def get_subscriber_client(self, credentials_file: str) \
            -> pubsub.subscriber.Client:
        """Get a subscriber client.

        :param credentials_file: Path to credentials file
        :return: Instance of subscriber client object created with the
            provided key
        """
        return pubsub.subscriber.Client.from_service_account_file(credentials_file)  # noqa: E501

    def get_subscription_path(self, project_id: str, subscription_name: str) \
            -> str:
        """Get the subscription path.

        :param project_id: Project ID
        :param subscription_name: Subscription name
        :return: String with the subscription path
        """
        return self.subscriber.subscription_path(project_id, subscription_name)

    def send_msg(self, msg: bytes):
        """Send an event to the Wazuh queue.

        :param msg: Event to be sent
        """
        event_json = json.dumps(self.format_msg(msg))
        event_final = f'{self.header}{event_json}'.encode(errors='replace')
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            s.send(event_final)
            s.close()
        except socket.error as e:
            if e.errno == 111:
                logging.critical('ERROR: Wazuh must be running')
                raise e
            else:
                logging.critical('ERROR: Error sending event to Wazuh')
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
        :return: Response of pull request. If the deadlide is exceeded,
            the method will return an empty PullResponse object
        """
        try:
            response = self.subscriber.pull(self.subscription_path,
                                            max_messages=max_messages,
                                            return_immediately=True)
        except google_exceptions.DeadlineExceeded:
            logging.warning('Deadline exceeded when pulling messages. '
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
                message_data = message.message.data
                logging.debug(f'Processing event:\n{message_data}')
                self.process_message(message.ack_id, message_data)
                processed_messages += 1  # increment processed_messages counter
            # get more messages
            response = self.pull_request(max_messages)

        return processed_messages


def get_script_arguments():
    """Get script arguments."""
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring Google Cloud",  # noqa: E501
                                     formatter_class=argparse.RawTextHelpFormatter)  # noqa: E501

    parser.add_argument('-i', '--project_id', dest='project_id',
                        help='Project ID', required=True)

    parser.add_argument('-s', '--subscription_name', dest='subscription_name',
                        help='Subscription name', required=True)

    parser.add_argument('-c', '--credentials_file', dest='credentials_file',
                        help='Path to credentials file', required=True)

    parser.add_argument('-m', '--max_messages', dest='max_messages', type=int,
                        help='Number of maximum messages pulled in each iteration',  # noqa: E501
                        required=False, default=100)

    parser.add_argument('-l', '--log_level', dest='log_level', type=int,
                        help='Log level', required=False, default=1)

    return parser.parse_args()


def set_logger(level: int = 1):
    """Set log level.

    :param level: Log level to be set
    """
    levels = {0: logging.NOTSET,
              1: logging.DEBUG,
              2: logging.INFO,
              3: logging.WARNING,
              4: logging.ERROR,
              5: logging.CRITICAL,
              }
    log_filename = f"gcloud-{datetime.date.today().strftime('%Y-%m-%d')}.log"
    logger_format = 'Google Cloud Wodle - %(levelno)s - %(funcName)s: %(message)s'  # noqa: E501
    logging.basicConfig(filename=log_filename, format=logger_format,
                        level=levels.get(level, logging.DEBUG))
