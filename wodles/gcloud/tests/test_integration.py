#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for integration module."""

import pytest
import sys
from unittest.mock import patch
from os.path import join, dirname, realpath

sys.path.append(join(dirname(realpath(__file__)), '..'))  # noqa: E501
from pubsub.subscriber import WazuhGCloudSubscriber
from logging import getLogger
test_data_path = join(dirname(realpath(__file__)), 'data')

credentials_file = 'credentials.json'
project = 'wazuh-dev'
subscription_id = 'testing'
test_message = 'test-message'
logger = getLogger('test_logger')


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def get_wazuhgcloud_subscriber(mock_client):
    """Return a WazuhGCloudSubscriber client."""
    client = WazuhGCloudSubscriber(credentials_file, project, logger, subscription_id)
    return client


@patch('integration.socket.socket')
def test_send_message_ok(mock_socket):
    """Test if messages are sent to Wazuh queue socket."""
    client = get_wazuhgcloud_subscriber()
    with client.initialize_socket():
        client.send_msg(test_message)
    mock_socket.return_value.send.assert_called()


def test_send_message_ko():
    """Test send_message method when the socket hasn't been initialized."""
    with pytest.raises(AttributeError):
        client = get_wazuhgcloud_subscriber()
        client.send_msg(test_message)


def test_format_msg():
    """Test if messages are formatted properly before to be sent."""
    client = get_wazuhgcloud_subscriber()
    formatted_message = client.format_msg(test_message)

    assert type(formatted_message) is str
