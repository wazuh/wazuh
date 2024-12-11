# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest

from wazuh.core.pyDaemonModule import *
from wazuh.core.exception import WazuhException
from tempfile import NamedTemporaryFile, TemporaryDirectory


@pytest.mark.parametrize('effect', [
   None,
   OSError(10000, 'Error')
])
@patch('wazuh.core.pyDaemonModule.sys.exit')
@patch('wazuh.core.pyDaemonModule.os.setsid')
@patch('wazuh.core.pyDaemonModule.sys.stderr.write')
@patch('wazuh.core.pyDaemonModule.sys.stdin.fileno')
@patch('wazuh.core.pyDaemonModule.os.dup2')
@patch('wazuh.core.pyDaemonModule.os.chdir')
def test_pyDaemon(mock_chdir, mock_dup, mock_fileno, mock_write, mock_setsid, mock_exit, effect):
    """Tests pyDaemon function works"""

    with patch('wazuh.core.pyDaemonModule.os.fork', return_value=255, side_effect=effect):
        pyDaemon()

    if effect == None:
        mock_exit.assert_called_with(0)
    else:
        mock_exit.assert_called_with(1)
    mock_setsid.assert_called_once_with()
    mock_chdir.assert_called_once_with('/')


@patch('wazuh.core.pyDaemonModule.common.WAZUH_RUN', new=Path('/tmp'))
def test_create_pid():
    """Tests create_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('wazuh.core.pyDaemonModule.common.WAZUH_RUN', new=Path('/tmp'))
@patch('wazuh.core.pyDaemonModule.os.chmod', side_effect=OSError)
def test_create_pid_ko(mock_chmod):
    """Tests create_pid function exception works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with pytest.raises(WazuhException, match=".* 3002 .*"):
            create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@pytest.mark.parametrize('process_name, expected_pid', [
   ('foo', 123),
   ('bar', 456),
   ('wazuh-apid', 789),
   ('wazuh-clusterd', None)
])
@patch('os.listdir', return_value=['foo-123.pid', 'bar-456.pid', 'wazuh-apid-789.pid'])
def test_get_parent_pid(os_listdir_mock, expected_pid, process_name):
    """Validates that the get_parent_pid function works as expected."""
    actual_pid = get_parent_pid(process_name)
    assert expected_pid == actual_pid


def test_delete_pid():
    """Tests delete_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.core.pyDaemonModule.common.WAZUH_RUN', new=Path(tmpdirname.split('/')[2])):
            delete_pid(tmpfile.name.split('/')[3].split('-')[0], '255')

@patch('wazuh.core.pyDaemonModule.next')
@patch('wazuh.core.pyDaemonModule.Path')
def test_get_wazuh_server_pid(path_mock, next_mock):
    """Validate that `get_wazuh_server_pid` works as expected."""
    pid = 123
    daemon_name = 'wazuh-server'
    wazuh_server_pid = f'{daemon_name}-{pid}'
    next_mock.return_value = MagicMock(stem=wazuh_server_pid)

    assert get_wazuh_server_pid(daemon_name) == pid


@patch('wazuh.core.pyDaemonModule.next', side_effect=StopIteration)
@patch('wazuh.core.pyDaemonModule.Path')
def test_get_wazuh_server_pid_ko(path_mock, next_mock):
    """Validate that `get_wazuh_server_pid` works as expected when the server is not running."""
    daemon_name = 'wazuh-server'
    with pytest.raises(StopIteration):
        get_wazuh_server_pid(daemon_name)


@patch('wazuh.core.pyDaemonModule.Path')
def test_get_running_processes(path_mock):
    """Validate that `get_running_processes` works as expected."""
    daemons = ['wazuh-server', 'wazuh-apid', 'wazuh-comms-apid', 'wazuh-engine']
    path_mock.return_value.glob.return_value = (MagicMock(stem=f'{daemon}-{i}') for i, daemon in enumerate(daemons))

    assert get_running_processes() == daemons


@pytest.mark.parametrize(
        'running_processes,expected',
        (
            (['wazuh-apid', 'wazuh-comms-apid', 'wazuh-engine'], True),
            (['wazuh-apid', 'wazuh-comms-apid'], True),
            ([], False),
        )
)
@patch('wazuh.core.pyDaemonModule.get_running_processes')
def test_check_for_daemons_shutdown(get_running_processes_mock, running_processes, expected):
    """Validate that `check_for_daemons_shutdown` works as expected."""
    daemons = ['wazuh-apid', 'wazuh-comms-apid', 'wazuh-engine']
    get_running_processes_mock.return_value = running_processes

    assert check_for_daemons_shutdown(daemons) == expected
