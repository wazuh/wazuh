# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_docker_listener.py -v --log-cli-level=DEBUG

import json
import logging
import os
import socket
import sys
from unittest.mock import MagicMock, patch, call

import pytest

logger = logging.getLogger(__name__)

# Mock the 'docker' module before importing DockerListener so the import
# does not fail in CI environments where Docker is not installed.
docker_mock = MagicMock()
sys.modules['docker'] = docker_mock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'docker-listener'))
import DockerListener as dl_module
from DockerListener import DockerListener


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

def test_max_event_size_imported():
    """DockerListener imports MAX_EVENT_SIZE from wodles/utils.py."""
    from utils import MAX_EVENT_SIZE
    logger.info("MAX_EVENT_SIZE imported by DockerListener => %d", dl_module.MAX_EVENT_SIZE)
    assert dl_module.MAX_EVENT_SIZE == MAX_EVENT_SIZE
    assert dl_module.MAX_EVENT_SIZE == 65535


def test_wait_time_default():
    """DockerListener.wait_time class attribute defaults to 5."""
    logger.info("DockerListener.wait_time => %d", DockerListener.wait_time)
    assert DockerListener.wait_time == 5


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

def test_init_sets_expected_attributes():
    """DockerListener.__init__ sets wazuh_queue, msg_header, and None client/threads."""
    listener = DockerListener()
    logger.info("wazuh_queue => %r", listener.wazuh_queue)
    logger.info("msg_header  => %r", listener.msg_header)
    assert listener.wazuh_queue.endswith(os.path.join('queue', 'sockets', 'queue'))
    assert listener.msg_header == '1:Wazuh-Docker:'
    assert listener.client is None
    assert listener.thread1 is None
    assert listener.thread2 is None


@patch('sys.platform', 'win32')
def test_init_exits_on_windows():
    """DockerListener.__init__ calls sys.exit(1) on Windows."""
    with pytest.raises(SystemExit) as exc_info:
        DockerListener()
    logger.info("SystemExit code on win32 => %s", exc_info.value.code)
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# format_msg — event parsing
# ---------------------------------------------------------------------------

def test_format_msg_wraps_json_in_docker_key():
    """format_msg returns a dict with 'integration' and 'docker' keys."""
    listener = DockerListener()
    raw = json.dumps({'status': 'start', 'Type': 'container'})
    result = listener.format_msg(raw)
    logger.info("format_msg(%r) => %r", raw, result)
    assert result['integration'] == 'docker'
    assert result['docker'] == {'status': 'start', 'Type': 'container'}


def test_format_msg_preserves_all_fields():
    """format_msg keeps all fields from the original JSON event."""
    listener = DockerListener()
    event = {'status': 'die', 'id': 'abc123', 'Actor': {'Attributes': {'exitCode': '0'}}}
    result = listener.format_msg(json.dumps(event))
    logger.info("format_msg docker payload => %r", result['docker'])
    assert result['docker']['id'] == 'abc123'
    assert result['docker']['Actor']['Attributes']['exitCode'] == '0'


# ---------------------------------------------------------------------------
# process — decodes bytes and delegates to send_msg
# ---------------------------------------------------------------------------

def test_process_decodes_event_and_calls_send_msg():
    """process decodes the raw bytes event and passes the string to send_msg."""
    listener = DockerListener()
    raw_event = json.dumps({'status': 'start'}).encode('utf-8')
    with patch.object(listener, 'send_msg') as mock_send:
        listener.process(raw_event)
        logger.info("send_msg called with => %s", mock_send.call_args)
        mock_send.assert_called_once_with(raw_event.decode('utf-8'))


# ---------------------------------------------------------------------------
# send_msg — normal path
# ---------------------------------------------------------------------------

@patch('DockerListener.socket.socket')
def test_send_msg_connects_and_sends(mock_socket_cls):
    """send_msg connects to wazuh_queue and sends the encoded message."""
    listener = DockerListener()
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    msg = json.dumps({'status': 'start'})
    listener.send_msg(msg)

    expected = '{}{}'.format(
        listener.msg_header,
        json.dumps(listener.format_msg(msg))
    ).encode()

    logger.info("send called with => %r", mock_sock.send.call_args)
    mock_sock.connect.assert_called_once_with(listener.wazuh_queue)
    mock_sock.send.assert_called_once_with(expected)
    mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# send_msg — MAX_EVENT_SIZE enforcement
# ---------------------------------------------------------------------------

@patch('DockerListener.socket.socket')
@patch('sys.stderr')
def test_send_msg_warns_when_event_exceeds_max_size(mock_stderr, mock_socket_cls):
    """send_msg writes a WARNING to stderr when the encoded message exceeds MAX_EVENT_SIZE."""
    listener = DockerListener()
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    # Build a message large enough to exceed MAX_EVENT_SIZE after encoding.
    oversized_payload = 'x' * dl_module.MAX_EVENT_SIZE
    msg = json.dumps({'data': oversized_payload})

    listener.send_msg(msg)

    warning_written = any(
        'WARNING' in str(c) and 'maximum allowed limit' in str(c)
        for c in mock_stderr.write.call_args_list
    )
    logger.info("stderr.write calls => %s", mock_stderr.write.call_args_list)
    assert warning_written


@patch('DockerListener.socket.socket')
@patch('sys.stderr')
def test_send_msg_no_warning_when_event_within_max_size(mock_stderr, mock_socket_cls):
    """send_msg does NOT write a WARNING when the message is within MAX_EVENT_SIZE."""
    listener = DockerListener()
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    msg = json.dumps({'status': 'start'})
    listener.send_msg(msg)

    warning_written = any(
        'WARNING' in str(c)
        for c in mock_stderr.write.call_args_list
    )
    logger.info("stderr.write calls => %s", mock_stderr.write.call_args_list)
    assert not warning_written


# ---------------------------------------------------------------------------
# send_msg — socket error handling
# ---------------------------------------------------------------------------

@patch('DockerListener.socket.socket')
@patch('sys.stderr')
def test_send_msg_exits_11_when_connection_refused(mock_stderr, mock_socket_cls):
    """send_msg exits with code 11 when errno 111 (connection refused) is raised."""
    listener = DockerListener()
    mock_sock = MagicMock()
    err = socket.error()
    err.errno = 111
    mock_sock.connect.side_effect = err
    mock_socket_cls.return_value = mock_sock

    with pytest.raises(SystemExit) as exc_info:
        listener.send_msg(json.dumps({'status': 'start'}))
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 11


@patch('DockerListener.socket.socket')
@patch('sys.stderr')
def test_send_msg_exits_13_on_other_socket_error(mock_stderr, mock_socket_cls):
    """send_msg exits with code 13 for any socket error other than errno 111."""
    listener = DockerListener()
    mock_sock = MagicMock()
    err = socket.error()
    err.errno = 99
    mock_sock.connect.side_effect = err
    mock_socket_cls.return_value = mock_sock

    with pytest.raises(SystemExit) as exc_info:
        listener.send_msg(json.dumps({'status': 'start'}))
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 13


@patch('DockerListener.socket.socket')
@patch('sys.stderr')
def test_send_msg_exits_13_on_generic_exception(mock_stderr, mock_socket_cls):
    """send_msg exits with code 13 for any non-socket exception."""
    listener = DockerListener()
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = Exception('unexpected')
    mock_socket_cls.return_value = mock_sock

    with pytest.raises(SystemExit) as exc_info:
        listener.send_msg(json.dumps({'status': 'start'}))
    logger.info("SystemExit code => %s", exc_info.value.code)
    assert exc_info.value.code == 13


# ---------------------------------------------------------------------------
# check_docker_service
# ---------------------------------------------------------------------------

def test_check_docker_service_returns_true_when_ping_succeeds():
    """check_docker_service returns True when docker.from_env().ping() succeeds."""
    listener = DockerListener()
    mock_client = MagicMock()
    with patch('DockerListener.docker.from_env', return_value=mock_client):
        result = listener.check_docker_service()
    logger.info("check_docker_service() => %r (ping ok)", result)
    assert result is True
    assert listener.client == mock_client


def test_check_docker_service_returns_false_when_ping_fails():
    """check_docker_service returns False when docker.from_env() raises."""
    listener = DockerListener()
    with patch('DockerListener.docker.from_env', side_effect=Exception('daemon not running')):
        result = listener.check_docker_service()
    logger.info("check_docker_service() => %r (ping failed)", result)
    assert result is False


# ---------------------------------------------------------------------------
# wait_time — reconnect delay
# ---------------------------------------------------------------------------

@patch('DockerListener.threading.Thread')
@patch('DockerListener.time.sleep')
def test_connect_sleeps_wait_time_while_docker_unavailable(mock_sleep, mock_thread):
    """connect() sleeps wait_time between retries while Docker is unavailable."""
    listener = DockerListener()
    listener.thread1 = MagicMock()
    # call sequence:
    #   #1 False: if self.check_docker_service()
    #   #2 False: while not self.check_docker_service()
    #   #3 True: while not self.check_docker_service()
    #   #4 True: if self.check_docker_service() (recursive)
    listener.check_docker_service = MagicMock(side_effect=[False, False, True, True])

    listener.connect(first_time=True)

    logger.info("time.sleep called with => %s", mock_sleep.call_args_list)
    mock_sleep.assert_called_once_with(listener.wait_time)
