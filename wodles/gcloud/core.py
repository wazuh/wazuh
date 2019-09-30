#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains tools for processing events from a Google Cloud subscription."""  # noqa: E501

import argparse
import json
import logging
import os
import socket
import sys

from google.cloud import pubsub_v1


HEADER = '1:Wazuh-GCloud:'
WAZUH_PATH = os.path.join('/', 'var', 'ossec')
WAZUH_QUEUE = os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue')


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
                        help='Credentials file', required=True)

    parser.add_argument('-m', '--max_messages', dest='max_messages', type=int,
                        help='Number of maximum messages pulled in each iteration',  # noqa: E501
                        required=False, default=100)

    parser.add_argument('-l', '--log_level', dest='log_level', type=int,
                        help='Log level', required=False, default=1)

    return parser.parse_args()


def get_subscriber_client(credentials_file: str) \
                          -> pubsub_v1.subscriber.Client:
    """Get a subscriber client.

    :param credentials_file: Path to credentials file
    :return: Instance of subscriber client object created with the provided key
    """
    return pubsub_v1.subscriber.Client.from_service_account_file(credentials_file)  # noqa: E501


def get_subscription_path(subscriber: pubsub_v1.SubscriberClient,
                          project_id: str, subscription_name: str) -> str:
    """Get the subscription path.

    :param subscriber:
    :param project_id:
    :param subscription_name:
    :return: String with the subscription path
    """
    return subscriber.subscription_path(project_id, subscription_name)


def process_message(subscriber: pubsub_v1.SubscriberClient,
                    subscription_path: str, ack_id: str, data: bytes):
    """Send a message to Wazuh queue.

    :param subscriber: SubscriberClient object
    :param subscription_path: Path to subscription
    :param ack_id: ACK_ID from event
    :param data: Data to be sent to Wazuh
    """
    send_msg(data)
    subscriber.acknowledge(subscription_path, [ack_id])


def check_permissions(subscriber: pubsub_v1.SubscriberClient,
                      subscription_path: str) -> bool:
    """Check if permissions are OK for executing the wodle.

    :param subscriber: SubscriberClient object
    :param subscription_path: Path to subscription
    :return: True if permissions are OK, False otherwise
    """
    required_permissions = {'pubsub.subscriptions.consume'}
    response = subscriber.test_iam_permissions(subscription_path,
                                               required_permissions)
    if required_permissions.difference(response.permissions) == set():
        return True
    else:
        return False


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

    logger_format = 'Google Cloud Wodle - %(levelno)s - %(funcName)s: %(message)s'  # noqa: E501
    logging.basicConfig(filename='gcloud.log', format=logger_format,
                        level=levels.get(level, logging.DEBUG))


def send_msg(msg: bytes):
    """Send an event to the Wazuh queue.

    :param msg: Event to be sent
    """
    json_event = json.dumps(format_msg(msg))
    event = f'{HEADER}{json_event}'
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        s.send(event.encode(encoding='utf-8', errors='ignore'))
        s.close()
    except socket.error as e:
        if e.errno == 111:
            logging.critical('Wazuh must be running')  # check if this function write in the log # noqa: E501
            sys.exit(1)
        else:
            logging.critical(f'Error sending event to Wazuh: {e}')


def format_msg(msg: bytes) -> str:
    """Format a message.

    :param msg: Message to be formatted
    """
    return msg.decode(encoding='utf-8', errors='ignore')
