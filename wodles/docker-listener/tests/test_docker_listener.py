# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import socket
import sys
from unittest.mock import call, patch, MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
docker_listener = __import__("DockerListener")


def test_DockerListener__init__():
    """Test if an instance of DockerListener is created properly."""
    dl = docker_listener.DockerListener()
    for attribute in ['wazuh_path', 'wazuh_queue', 'msg_header', 'client', 'thread1', 'thread2']:
        assert hasattr(dl, attribute)


@patch('sys.platform', 'win32')
@patch('sys.stderr.write')
def test_DockerListener__init__ko(mock_stderr):
    """Test DockerListener exists if attempting to run in Windows environments."""
    with pytest.raises(SystemExit) as err:
        docker_listener.DockerListener()
    assert err.value.code == 1
    mock_stderr.assert_called_once()


@patch('DockerListener.threading.Thread')
@patch('DockerListener.DockerListener.connect')
@patch('DockerListener.DockerListener.send_msg')
def test_DockerListener_start(mock_send, mock_connect, mock_thread):
    """Test if start creates the expected Threads and calls to the connect function."""
    dl = docker_listener.DockerListener()
    dl.start()
    mock_send.assert_called_once()
    mock_connect.assert_called_with(first_time=True)
    mock_thread.assert_has_calls([call(target=dl.listen), call(target=dl.listen)])
    assert dl.thread1
    assert dl.thread2


@pytest.mark.parametrize('first_time', [True, False])
@pytest.mark.parametrize('alive', [True, False])
@patch('DockerListener.threading.Thread')
@patch('DockerListener.DockerListener.send_msg')
@patch('DockerListener.DockerListener.check_docker_service', return_value=True)
def test_DockerListener_connect(mock_service, mock_send, mock_thread, first_time, alive):
    """Test DockerListener successfully connects to the Docker service by starting the expected thread."""
    dl = docker_listener.DockerListener()
    m = MagicMock()
    m.is_alive.return_value = alive
    dl.thread1 = m

    dl.connect(first_time=first_time)

    mock_service.assert_called_once()

    if first_time:
        dl.thread1.start.assert_called_once()
    elif alive:
        mock_thread.assert_called_with(target=dl.listen)
        dl.thread2.start.assert_called_once()
    else:
        mock_thread.assert_called_with(target=dl.listen)
        dl.thread1.start.assert_called_once()

    mock_send.assert_called_once()


@pytest.mark.parametrize('first_time', [True, False])
@patch('DockerListener.threading.Thread')
@patch('DockerListener.time.sleep')
@patch('DockerListener.DockerListener.check_docker_service')
@patch('DockerListener.DockerListener.send_msg')
def test_DockerListener_connect_ko(mock_send, mock_service, mock_time, mock_thread, first_time):
    """Test connect function will attempt to reconnect to the docker service until accomplished."""
    docker_service_values = [False, False, True, True]
    mock_service.side_effect = docker_service_values

    dl = docker_listener.DockerListener()
    dl.thread1 = MagicMock()
    dl.thread1.is_alive.return_value = False

    dl.connect(first_time=first_time)

    assert mock_service.call_count == len(docker_service_values)
    assert mock_send.call_count == 2 if first_time else 1
    mock_time.assert_called_with(dl.wait_time)
    mock_thread.assert_called_with(target=dl.listen)
    dl.thread1.start.assert_called_once()


@patch('DockerListener.docker.from_env', return_value=MagicMock())
def test_DockerListener_check_docker_service(mock_env):
    """Test check_docker_service verifies the docker service status."""
    dl = docker_listener.DockerListener()
    is_running = dl.check_docker_service()
    mock_env.assert_called_once()
    dl.client.ping.assert_called_once()
    assert is_running


@patch('DockerListener.docker.from_env', Exception)
def test_DockerListener_check_docker_service_ko():
    """Test check_docker_service returns False when the service is not running."""
    dl = docker_listener.DockerListener()
    assert not dl.check_docker_service()


@patch('DockerListener.DockerListener.connect')
@patch('DockerListener.DockerListener.send_msg')
@patch('DockerListener.DockerListener.process')
def test_DockerListener_listen(mock_process, mock_send, mock_connect):
    """Test listen function process every event received from the client."""
    event_list = [1, 2, 3]
    dl = docker_listener.DockerListener()
    dl.client = MagicMock()
    dl.client.events.return_value = event_list
    dl.listen()
    mock_process.assert_has_calls([call(x) for x in event_list])
    mock_send.assert_called_once()
    mock_connect.assert_called_once()


@patch('DockerListener.DockerListener.connect')
@patch('DockerListener.DockerListener.send_msg')
@patch('DockerListener.DockerListener.process')
def test_DockerListener_listen_ko(mock_process, mock_send, mock_connect):
    """Test listen raises an exception when is caught."""
    dl = docker_listener.DockerListener()
    dl.client = MagicMock()
    dl.client.events.side_effect = Exception
    with pytest.raises(Exception):
        dl.listen()
    mock_process.assert_not_called()
    mock_send.assert_not_called()
    mock_connect.assert_not_called()


@patch('DockerListener.DockerListener.send_msg')
def test_DockerListener_process(mock_send):
    """Test process function sends the decoded events to the Wazuh socket."""
    event = b"test"
    dl = docker_listener.DockerListener()
    dl.process(event)
    mock_send.assert_called_with(event.decode("utf-8"))


def test_DockerListener_format_msg():
    """Test format_msg returns a dict with the expected key and values."""
    msg = '{"test": "value"}'
    dl = docker_listener.DockerListener()
    result = dl.format_msg(msg)
    assert isinstance(result, dict)
    assert result.get("integration") == "docker"
    assert result.get("docker") == json.loads(msg)


@patch('DockerListener.socket.socket')
def test_DockerListener_send_msg(mock_socket):
    """Test send_msg sends the messages with the expected contents to the Wazuh socket."""
    msg = '{"test": "value"}'

    m = MagicMock()
    mock_socket.return_value = m
    dl = docker_listener.DockerListener()
    dl.send_msg(msg)

    mock_socket.assert_called_with(socket.AF_UNIX, socket.SOCK_DGRAM)
    m.connect.assert_called_with(dl.wazuh_queue)
    formatted_msg = json.dumps(dl.format_msg(msg))
    m.send.assert_called_with(f"{dl.msg_header}{formatted_msg}".encode())
    m.close.assert_called_once()


@pytest.mark.parametrize('exception_code, exit_code', [
    (111, 11),
    (1, 13),
    (None, 13)
])
@patch('sys.stderr.write')
@patch('DockerListener.json', MagicMock())
@patch('DockerListener.socket.socket')
def test_DockerListener_send_msg_ko(mock_socket, mock_stderr, exception_code, exit_code):
    """Test send_message handle the socket exceptions."""
    if exception_code:
        s = socket.error()
        s.errno = exception_code
        mock_socket.side_effect = s
    else:
        mock_socket.side_effect = Exception

    dl = docker_listener.DockerListener()

    with pytest.raises(SystemExit) as err:
        dl.send_msg("")
    assert err.value.code == exit_code
    mock_stderr.assert_called_once()
