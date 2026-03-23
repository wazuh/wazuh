#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for subscriber module."""

import os
import sys
from logging import Logger
from unittest.mock import MagicMock
from unittest.mock import call, patch

import pytest
from google.api_core import exceptions as google_exceptions

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from pubsub.subscriber import WazuhGCloudSubscriber
from exceptions import GCloudError


data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/')
MAX_MESSAGES = 100


def get_wodle_config(credentials_file: str = "credentials.json", project: str = "test_project",
                     subscription_id: str = "test_subscription", logger: Logger = None) -> dict:
    """Return a dict containing every parameter supported by WazuhGCloudSubscriber. Used to simulate different
    ossec.conf configurations.

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

    Returns
    -------
    dict
        A dict containing the configuration parameters with their values
    """
    return {'credentials_file': credentials_file, 'project': project, 'subscription_id': subscription_id,
            'logger': logger if logger else MagicMock()}


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber__init__(mock_client):
    """Test if an instance of WazuhGCloudSubscriber is created properly."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    for attribute in ['logger', 'subscriber', 'subscription_path']:
        assert hasattr(pubsub, attribute)
    mock_client.assert_called_once()


@pytest.mark.parametrize('credentials_file, errcode', [
    ('invalid_credentials_file.json', 1000),
    ('unexistent_file', 1001)
])
def test_WazuhGCloudSubscriber__init__ko(credentials_file, errcode):
    """Test that the appropriate exceptions are raised when the WazuhGCloudSubscriber constructor is called with
    invalid parameters.
    """
    with pytest.raises(GCloudError) as e:
        WazuhGCloudSubscriber(**get_wodle_config(credentials_file=os.path.join(data_path, credentials_file)))
    assert e.value.errcode == errcode


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_get_subscriber_client(mock_credentials):
    """Test get_subscriber_client attempts to create a client object using the provided credentials file."""
    WazuhGCloudSubscriber.get_subscriber_client("credentials.json")
    mock_credentials.assert_called_with("credentials.json")


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_get_subscription_path(mock_credentials):
    """Test get_subscription_path calls the subscription_path with the expected parameters."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    pubsub.subscriber = MagicMock()
    pubsub.get_subscription_path(project="project", subscription_id="subscription")
    pubsub.subscriber.subscription_path.assert_called_with("project", "subscription")


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_check_permissions(mock_credentials):
    """Test check_permissions to make sure it checks the required permissions to be present for the subscriber."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    pubsub.subscriber.test_iam_permissions.return_value = MagicMock(permissions={'pubsub.subscriptions.consume'})
    pubsub.check_permissions()
    mock_credentials.assert_called_once()


@pytest.mark.parametrize('errcode, msg', [
    (1204, ""),
    (1205, "project not found or user does not have access"),
    (1206, "")
])
@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_check_permissions_ko(mock_credentials, errcode, msg):
    """Test check_permissions raises the expected GCloudError when the subscriber does not have the required
    permissions."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config(credentials_file="credentials"))
    if errcode != 1206:
        pubsub.subscriber.test_iam_permissions.side_effect = google_exceptions.NotFound(msg)
    with pytest.raises(GCloudError) as e:
        pubsub.check_permissions()
    assert e.value.errcode == errcode
    mock_credentials.assert_called_once()


@pytest.mark.parametrize('num_messages', [1, 10, 100])
@patch('pubsub.subscriber.WazuhGCloudSubscriber.send_msg')
@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_pull_request(mock_credentials, mock_send_msg, num_messages):
    """Test pull_request makes the request using the provided parameters and returns the expected number of messages."""
    # Create a large list of fake messages
    message_list = [MagicMock() for _ in range(100)]
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    pubsub.subscriber.pull.return_value = MagicMock(received_messages=message_list[:num_messages])
    assert pubsub.pull_request(max_messages=num_messages) == num_messages
    pubsub.subscriber.pull.assert_called_with(request={'subscription': pubsub.subscription_path,
                                                       'max_messages': num_messages})


@patch('pubsub.subscriber.WazuhGCloudSubscriber.send_msg')
@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_pull_request_ko(mock_credentials, mock_send_msg):
    """Test pull_request returns no messages when an exception is raised."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    pubsub.subscriber.pull.side_effect = google_exceptions.DeadlineExceeded("placeholder")
    assert pubsub.pull_request(max_messages=MAX_MESSAGES) == 0


@patch('pubsub.subscriber.pubsub.subscriber.Client.from_service_account_file')
def test_WazuhGCloudSubscriber_process_messages(mock_credentials):
    """Test process_messages invoke the pull_request function several times until the required number of messages is
    returned."""
    pubsub = WazuhGCloudSubscriber(**get_wodle_config())
    pubsub.initialize_socket = MagicMock()
    pubsub.pull_request = MagicMock(return_value=MAX_MESSAGES/2)
    assert pubsub.process_messages(max_messages=MAX_MESSAGES) == MAX_MESSAGES
    pubsub.pull_request.assert_has_calls([call(MAX_MESSAGES), call(MAX_MESSAGES/2)])
