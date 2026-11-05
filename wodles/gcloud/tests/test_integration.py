#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for integration module."""

import errno
import json
import socket
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


@pytest.mark.parametrize('raised_exception', [
    ConnectionRefusedError(errno.ECONNREFUSED, 'Connection refused'),
    OSError(errno.ENOBUFS, 'No buffer space available'),
])
def test_WazuhGCloudIntegration_send_message_ko_not_skipped(raised_exception):
    """Test send_message still aborts on socket errors other than a message too long for the socket."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    integration.socket = MagicMock()
    integration.socket.send.side_effect = raised_exception
    with pytest.raises(exceptions.WazuhIntegrationInternalError) as e:
        integration.send_msg(test_message)
    assert e.value.errcode == 3
    integration.logger.error.assert_not_called()


def test_WazuhGCloudIntegration_send_message_skips_message_too_long():
    """Test send_message logs and skips an event the socket rejects as too long, instead of aborting."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    integration.socket = MagicMock()
    integration.socket.send.side_effect = OSError(errno.EMSGSIZE, 'Message too long')
    integration.send_msg(test_message)
    integration.logger.error.assert_called_once()


def test_WazuhGCloudIntegration_send_message_too_long_real_socket():
    """Test the error a real datagram socket raises for an oversized event is the one send_message skips, and the
    socket keeps working for the next event."""
    integration = WazuhGCloudIntegration(logger=MagicMock())
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    with sender, receiver:
        # A small send buffer makes the overflow size independent of the host's net.core.wmem_default
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        receiver.setblocking(False)
        integration.socket = sender

        integration.send_msg('x' * sender.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
        integration.send_msg(test_message)

        assert receiver.recv(65536) == f'{WazuhGCloudIntegration.header}{test_message}'.encode()
        with pytest.raises(BlockingIOError):
            receiver.recv(65536)
    integration.logger.error.assert_called_once()
