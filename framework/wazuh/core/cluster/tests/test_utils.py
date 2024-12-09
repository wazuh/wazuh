# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import json
import os
import socket
import sys
import pathlib
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.getgrnam'):
    with patch('wazuh.core.common.getpwnam'):
        with patch('wazuh.core.common.wazuh_uid'):
            with patch('wazuh.core.common.wazuh_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core import common
                from wazuh.core.cluster import utils
                from wazuh.core.exception import (
                    WazuhError,
                    WazuhException,
                    WazuhInternalError,
                    WazuhPermissionError,
                    WazuhResourceNotFound,
                    WazuhHAPHelperError
                )
                from wazuh.core.results import WazuhResult

default_cluster_config = {
    'node_type': 'master',
    'node_name': 'node01',
    'port': 1516,
    'bind_addr': 'localhost',
    'nodes': ['127.0.0.1'],
    'hidden': 'no',
    'cafile': common.WAZUH_ETC / 'server.ca',
    'certfile': common.WAZUH_ETC / 'server.crt',
    'keyfile': common.WAZUH_ETC / 'server.key',
    'keyfile_password': '',
}


def test_ping_unix_socket_file_does_not_exist():
    """Verify ping_unix_socket returns False when the socket file does not exist."""
    with patch("pathlib.Path.exists", return_value=False):
        assert not utils.ping_unix_socket(pathlib.Path("/tmp/nonexistent_socket"))


@pytest.mark.parametrize('timeout', (None, 10))
def test_ping_unix_socket_successful(timeout: int | None):
    """Verify a successful connection to the UNIX socket."""
    with patch("pathlib.Path.exists", return_value=True), \
            patch("socket.socket") as mock_socket:
        mock_client = MagicMock()
        mock_socket.return_value = mock_client
        socket_path = pathlib.Path("/tmp/existing_socket")

        assert utils.ping_unix_socket(socket_path, timeout) is True
        mock_client.settimeout.assert_called_once_with(timeout)
        mock_client.connect.assert_called_once_with(str(socket_path))
        mock_client.close.assert_called_once()


def test_ping_unix_socket_connection_timeout():
    """Verify ping_unix_socket returns False when the connection to the UNIX socket times out."""
    with patch("pathlib.Path.exists", return_value=True), \
            patch("socket.socket") as mock_socket:
        mock_client = MagicMock()
        mock_client.connect.side_effect = socket.timeout
        mock_socket.return_value = mock_client
        socket_path = pathlib.Path("/tmp/existing_socket")

        assert not utils.ping_unix_socket(socket_path)
        mock_client.connect.assert_called_once_with(str(socket_path))


def test_ping_unix_socket_error():
    """Verify ping_unix_socket returns False when there is a generic socket error."""
    with patch("pathlib.Path.exists", return_value=True), \
         patch("socket.socket") as mock_socket:
        mock_client = MagicMock()
        mock_client.connect.side_effect = socket.error("Test error")
        mock_socket.return_value = mock_client
        socket_path = pathlib.Path("/tmp/existing_socket")

        assert not utils.ping_unix_socket(socket_path)
        mock_client.connect.assert_called_once_with(str(socket_path))


@pytest.mark.parametrize(
        'config',
        (
            {
                utils.HAPROXY_DISABLED: 'no',
                utils.HAPROXY_ADDRESS: 'test',
                utils.HAPROXY_PASSWORD: 'test',
                utils.HAPROXY_USER: 'test'
            },
            {
                utils.HAPROXY_DISABLED: 'no',
                utils.HAPROXY_ADDRESS: 'test',
                utils.HAPROXY_PASSWORD: 'test',
                utils.HAPROXY_USER: 'test',
                utils.FREQUENCY: '60',
                utils.AGENT_CHUNK_SIZE: '120',
                utils.IMBALANCE_TOLERANCE: '0.1'
            }
        )
)
def test_parse_haproxy_helper_config(config: dict):
    """Verify that parse_haproxy_helper_config function returns the default configuration."""

    ret_val = utils.parse_haproxy_helper_config(config)

    for key in ((config.keys()) | utils.HELPER_DEFAULTS.keys()):
        assert key in ret_val

        assert isinstance(ret_val[utils.HAPROXY_DISABLED], bool)

        if key in [
            utils.FREQUENCY,
            utils.AGENT_CHUNK_SIZE,
            utils.AGENT_RECONNECTION_STABILITY_TIME,
            utils.AGENT_RECONNECTION_TIME,
            utils.REMOVE_DISCONNECTED_NODE_AFTER,
            utils.HAPROXY_PORT
        ]:
            assert isinstance(ret_val[key], int)

        if key in [utils.IMBALANCE_TOLERANCE]:
            assert isinstance(ret_val[key], float)


@pytest.mark.parametrize(
    'config, exception_type, expected_error_code',
    [
        (
            {
                utils.HAPROXY_DISABLED: 'no',
                utils.HAPROXY_ADDRESS: 'test',
                utils.HAPROXY_PASSWORD: 'test',
                utils.HAPROXY_USER: 'test',
                utils.FREQUENCY: 'bad',
            },
            WazuhError,
            '3004'
        ),
        (
            {
                utils.HAPROXY_DISABLED: 'no',
                utils.HAPROXY_ADDRESS: 'test',
                utils.HAPROXY_PASSWORD: 'test',
                utils.HAPROXY_USER: 'test',
                utils.IMBALANCE_TOLERANCE: 'bad'
            },
            WazuhError,
            '3004'
        ),
        (
            {
                utils.HAPROXY_DISABLED: 'no',
                utils.HAPROXY_ADDRESS: 'test',
                utils.HAPROXY_PASSWORD: 'test',
                utils.HAPROXY_USER: 'test',
                utils.HAPROXY_PROTOCOL: 'https'
            },
            WazuhHAPHelperError,
            '3042'
        )
    ]
)
def test_parse_haproxy_helper_config_ko(config: dict, exception_type: WazuhException, expected_error_code: str):
    """Verify that parse_haproxy_helper_config function raises when config has an invalid type."""

    with pytest.raises(exception_type, match=f'.* {expected_error_code} .*'):
        utils.parse_haproxy_helper_config(config)


def test_get_manager_status():
    """Check that get_manager_status function returns the manager status.

    For this test, the status can be stopped or failed.
    """
    called = 0

    def exist_mock(path):
        if '.failed' in path and called == 0:
            return True
        elif '.restart' in path and called == 1:
            return True
        elif '.start' in path and called == 2:
            return True
        elif '/proc' in path and called == 3:
            return True
        else:
            return False

    status = utils.get_manager_status()
    for value in status.values():
        assert value == 'stopped'

    with patch('wazuh.core.cluster.utils.glob', return_value=['ossec-0.pid']):
        with patch('re.match', return_value='None'):
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'failed'

        # with patch('wazuh.core.cluster.utils.join', return_value='failed') as join_mock:
        with patch('wazuh.core.cluster.utils.os.path.exists', side_effect=exist_mock):
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'failed'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'restarting'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'starting'

            called += 1
            status = utils.get_manager_status()
            for value in status.values():
                assert value == 'running'

@pytest.mark.parametrize('exc', [
    PermissionError,
    FileNotFoundError
])
@patch('os.stat')
def test_get_manager_status_ko(mock_stat, exc):
    """Check that get_manager_status function correctly handles expected exceptions.

    Parameters
    ----------
    exc : Exception
        Expected exception to be handled.
    """
    mock_stat.side_effect = exc
    with pytest.raises(WazuhInternalError, match='.* 1913 .*'):
        utils.get_manager_status()


def test_get_cluster_status():
    """Check if cluster is enabled and running. Also check that cluster is shown as not running when a
    WazuhInternalError is raised."""
    status = utils.get_cluster_status()
    assert {'running': 'no'} == status

    with patch('wazuh.core.cluster.utils.get_manager_status', side_effect=WazuhInternalError(1913)):
        status = utils.get_cluster_status()
        assert {'running': 'no'} == status


def test_manager_restart():
    """Verify that manager_restart send to the manager the restart request."""
    with patch('wazuh.core.cluster.utils.open', side_effect=None):
        with patch('fcntl.lockf', side_effect=None):
            with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                utils.manager_restart()

            with patch('os.path.exists', return_value=True):
                with pytest.raises(WazuhInternalError, match='.* 1902 .*'):
                    utils.manager_restart()

                with patch('socket.socket.connect', side_effect=None):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        utils.manager_restart()

                    with patch('socket.socket.send', side_effect=None):
                        status = utils.manager_restart()
                        assert WazuhResult({'message': 'Restart request sent'}) == status


def test_ClusterFilter():
    """Verify that ClusterFilter adds cluster related information into cluster logs"""
    cluster_filter = utils.ClusterFilter(tag='Cluster', subtag='config')
    record = utils.ClusterFilter(tag='Testing', subtag='config')
    record.update_tag(new_tag='Testing_tag')
    record.update_subtag(new_subtag='Testing_subtag')

    assert cluster_filter.filter(record=record)


def test_ClusterLogger():
    """Verify that ClusterLogger defines the logger used by wazuh-server."""
    cluster_logger = utils.ClusterLogger(tag='%(asctime)s %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s',
                                         debug_level=1)
    cluster_logger.setup_logger()

    assert cluster_logger.logger.level == logging.DEBUG



def test_log_subprocess_execution():
    """Check that the passed messages from subprocesses are logged with the expected level."""
    logs = {'debug': {'example_debug': ["Debug level message."]},
            'debug2': {'example_debug2': ["Debug2 level message."]},
            'warning': {'example_debug2': ["Warning level message."]},
            'error': {'example_error': ["Error level message."]},
            'generic_errors': ['First generic error to be logged', 'Second generic error to be logged'],
            }
    with patch.object(utils.logger, 'debug') as debug_logger, \
            patch.object(utils.logger, 'debug2') as debug2_logger, \
            patch.object(utils.logger, 'warning') as warning_logger, \
            patch.object(utils.logger, 'error') as error_logger:
        utils.log_subprocess_execution(utils.logger, logs)
        debug_logger.assert_called_with(f"{dict(logs['debug'])}")
        debug2_logger.assert_called_with(f"{dict(logs['debug2'])}")
        warning_logger.assert_called_with(f"{dict(logs['warning'])}")
        error_logger.assert_any_call(f"{dict(logs['error'])}")
        for error in logs['generic_errors']:
            error_logger.assert_any_call(error, exc_info=False)


@patch('os.getpid', return_value=0000)
@patch('wazuh.core.cluster.utils.pyDaemonModule.create_pid')
def test_process_spawn_sleep(pyDaemon_create_pid_mock, get_pid_mock):
    """Check if the cluster pool is properly spawned."""

    child = 1
    utils.process_spawn_sleep(child)

    pyDaemon_create_pid_mock.assert_called_once_with(f'wazuh-server_child_{child}', get_pid_mock.return_value)


@pytest.mark.asyncio
@patch('concurrent.futures.ThreadPoolExecutor')
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI')
async def test_forward_function(distributed_api_mock, concurrent_mock):
    """Check if the function is correctly distributed to the master node."""

    class ThreadPoolExecutorMock:
        """Auxiliary class."""

        def submit(self, run, function):
            return DAPIMock()

    class DAPIMock:
        """Auxiliary class."""

        def __init__(self):
            pass

        def distribute_function(self):
            pass

        @staticmethod
        def result():
            return 'mock'

    def auxiliary_func():
        """Auxiliary function."""
        pass

    distributed_api_mock.return_value = DAPIMock()
    concurrent_mock.return_value = ThreadPoolExecutorMock()
    assert await utils.forward_function(auxiliary_func) == DAPIMock().result()
    distributed_api_mock.assert_called_once()
    concurrent_mock.assert_called_once()


@pytest.mark.parametrize(
    'cluster_config,expected',
    (
        [{'node_type': 'master'}, True],
        [{'node_type': 'worker'}, False],
    )
)
@patch('wazuh.core.cluster.utils.read_cluster_config')
def test_running_on_master_node(read_cluster_config_mock, cluster_config, expected):
    """
    Test that running_on_master function returns the expected value,
    based on combinations of disabled/enabled and node type.
    """

    read_cluster_config_mock.return_value = cluster_config

    assert utils.running_in_master_node() == expected

@pytest.mark.parametrize('result', [
    WazuhError(6001),
    WazuhInternalError(1000),
    WazuhPermissionError(4000),
    WazuhResourceNotFound(1710),
    'value',
    1,
    False,
    {'key': 'value'}
])
def test_raise_if_exc(result):
    """Check that raise_if_exc raises an exception if the result is one."""
    if isinstance(result, Exception):
        with pytest.raises(Exception):
            utils.raise_if_exc(result)
    else:
        utils.raise_if_exc(result)
