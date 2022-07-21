#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for integration module."""

import json
import sys
from os.path import join, dirname, realpath
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

sys.path.append(join(dirname(realpath(__file__)), '..'))  # noqa: E501
from integration import WazuhGCloudIntegration, ANALYSISD
import exceptions


test_data_path = join(dirname(realpath(__file__)), 'data')
test_message = 'test-message'


def test_WazuhGCloudIntegration__init__():
    """Test if an instance of WazuhGCloudIntegration is created properly."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    for attribute in ['logger', 'socket']:
        assert hasattr(integration, attribute)


def test_WazuhGCloudIntegration_format_msg():
    """Test format_msg returns a well-formatted message."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    msg = integration.format_msg(json.dumps(test_message))
    assert isinstance(msg, str)
    msg_json = json.loads(msg)
    assert msg_json.get('integration') == 'gcp'
    assert msg_json.get('gcp') == test_message


@patch('integration.socket.socket')
def test_WazuhGCloudIntegration_initialize_socket(mock_socket):
    """Test initialize_socket establish a connection with the ANALYSISD socket."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    integration.initialize_socket()
    integration.socket.connect.assert_called_with(ANALYSISD)


@pytest.mark.parametrize('raised_exception, errcode', [
    (ConnectionRefusedError, 1),
    (OSError, 2)
])
def test_WazuhGCloudIntegration_initialize_socket_ko(raised_exception, errcode):
    """Test initialize_socket properly handles exceptions."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    with patch('socket.socket', side_effect=raised_exception), pytest.raises(exceptions.WazuhIntegrationInternalError) as e:
        integration.initialize_socket()
    assert errcode == e.value.errcode


def test_WazuhGCloudIntegration_process_data():
    """Test process_data is not implemented for this base class."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    with pytest.raises(NotImplementedError):
        integration.process_data()


@patch('integration.socket.socket')
def test_WazuhGCloudIntegration_send_message(mock_socket):
    """Test if messages are sent to Wazuh queue socket."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    with integration.initialize_socket():
        integration.send_msg(test_message)
    mock_socket.return_value.send.assert_called_with(
        f'{WazuhGCloudIntegration.header}{test_message}'.encode(errors='replace'))


def test_WazuhGCloudIntegration_send_message_ko():
    """Test send_message when the socket hasn't been initialized."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    integration.socket = MagicMock()
    integration.socket.send.side_effect = OSError
    with pytest.raises(exceptions.WazuhIntegrationInternalError) as e:
        integration.send_msg(test_message)
    assert e.value.errcode == 3
