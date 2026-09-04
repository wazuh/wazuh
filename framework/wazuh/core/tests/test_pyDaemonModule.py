# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch
import logging
import os

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


@patch('wazuh.core.pyDaemonModule.common.WAZUH_PATH', new='/tmp')
def test_create_pid():
    """Tests create_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('wazuh.core.pyDaemonModule.common.WAZUH_PATH', new='/tmp')
@patch('wazuh.core.pyDaemonModule.os.chmod', side_effect=OSError)
def test_create_pid_ko(mock_chmod):
    """Tests create_pid function exception works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            with pytest.raises(WazuhException, match=".* 3002 .*"):
                create_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('wazuh.core.pyDaemonModule.common.WAZUH_PATH', new='/tmp')
def test_delete_pid():
    """Tests delete_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.core.pyDaemonModule.common.OS_PIDFILE_PATH', new=tmpdirname.split('/')[2]):
            delete_pid(tmpfile.name.split('/')[3].split('-')[0], '255')


@patch('wazuh.core.pyDaemonModule.common.OS_PIDFILE_PATH', new='')
@patch('wazuh.core.pyDaemonModule.psutil.Process')
def test_delete_child_pids_matches_pid_exactly(mock_process):
    """A child's pidfile is matched by its exact PID: killing PID 16 must not remove PID 161's file."""
    with TemporaryDirectory() as tmpdirname:
        for pid in (16, 161):
            open(os.path.join(tmpdirname, f'wazuh-manager-apid_auth-{pid}.pid'), 'w').close()
        child = MagicMock(pid=16)
        mock_process.return_value.children.return_value = [child]

        with patch('wazuh.core.pyDaemonModule.common.WAZUH_PATH', new=tmpdirname):
            delete_child_pids('wazuh-manager-apid', 1234, logging.getLogger('test'))

        child.kill.assert_called_once()
        assert not os.path.exists(os.path.join(tmpdirname, 'wazuh-manager-apid_auth-16.pid'))
        assert os.path.exists(os.path.join(tmpdirname, 'wazuh-manager-apid_auth-161.pid'))
