#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from datetime import datetime, timezone
from unittest.mock import ANY, patch
from uuid import uuid4

import pytest
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin
from wazuh.core.server.tests.conftest import get_default_configuration

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

        from wazuh.core.manager import *

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager')
ossec_log_path = '{0}/ossec_log.log'.format(test_data_path)
ossec_log_json_path = '{0}/ossec_log.log'.format(test_data_path)


class InitManager:
    """Initialization manager mock."""

    def __init__(self):
        """Initialize the environment for testing manager functions."""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')


@pytest.fixture(scope='module')
def test_manager():
    """Fixture to initialize and return an instance of InitManager for testing."""
    # Set up
    test_manager = InitManager()
    return test_manager


@pytest.fixture
def client_session_get_mock():
    """Fixture to mock the `httpx.AsyncClient.get` method for testing."""
    with patch('httpx.AsyncClient.get') as get_mock:
        yield get_mock


@pytest.fixture
def installation_uid():
    """Fixture to generate and return a unique installation UID for testing."""
    return str(uuid4())


def get_logs(json_log: bool = False):
    """Read and return logs from the specified file (JSON or plain text)."""
    with open(ossec_log_json_path if json_log else ossec_log_path) as f:
        return f.read()


@pytest.mark.parametrize('process_status', ['running', 'stopped', 'failed', 'restarting', 'starting'])
@patch('os.path.exists')
@patch('wazuh.core.manager.glob')
def test_get_server_status(manager_glob, manager_exists, test_manager, process_status):
    """Tests core.manager.get_server_status().

    Tests manager.status() function in two cases:
        * PID files are created and processed are running,
        * No process is running and therefore no PID files have been created
    """

    def mock_glob(path_to_check):
        return [path_to_check.replace('*', '0234')] if process_status == 'running' else []

    def mock_exists(path_to_check):
        if path_to_check == '/proc/0234':
            return process_status == 'running'
        else:
            return path_to_check.endswith(
                f'.{process_status.replace("ing", "").replace("re", "")}'
            ) or path_to_check.endswith(f'.{process_status.replace("ing", "")}')

    manager_glob.side_effect = mock_glob
    manager_exists.side_effect = mock_exists
    manager_status = get_server_status()
    assert isinstance(manager_status, dict)
    assert all(process_status == x for x in manager_status.values())
    if process_status == 'running':
        manager_exists.assert_any_call('/proc/0234')


def test_get_server_status_calls():  # noqa: C901
    """Validate `get_server_status` function calls.

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

    status = get_server_status()
    for value in status.values():
        assert value == 'stopped'

    with patch('wazuh.core.manager.glob', return_value=['ossec-0.pid']):
        with patch('re.match', return_value='None'):
            status = get_server_status()
            for value in status.values():
                assert value == 'failed'

        with patch('wazuh.core.manager.os.path.exists', side_effect=exist_mock):
            status = get_server_status()
            for value in status.values():
                assert value == 'failed'

            called += 1
            status = get_server_status()
            for value in status.values():
                assert value == 'restarting'

            called += 1
            status = get_server_status()
            for value in status.values():
                assert value == 'starting'

            called += 1
            status = get_server_status()
            for value in status.values():
                assert value == 'running'


@pytest.mark.parametrize('exc', [PermissionError, FileNotFoundError])
@patch('os.stat')
def test_get_server_status_ko(mock_stat, exc):
    """Check that get_server_status function correctly handles expected exceptions."""
    mock_stat.side_effect = exc
    with pytest.raises(WazuhInternalError, match='.* 1913 .*'):
        get_server_status()


def test_get_ossec_log_fields():
    """Test get_ossec_log_fields() method returns a tuple."""
    result = get_ossec_log_fields('2020/07/14 06:10:40 rootcheck: INFO: Ending rootcheck scan.')
    assert isinstance(result, tuple), 'The result is not a tuple'
    assert result[0] == datetime(2020, 7, 14, 6, 10, 40, tzinfo=timezone.utc)
    assert result[1] == 'wazuh-rootcheck'
    assert result[2] == 'info'
    assert result[3] == ' Ending rootcheck scan.'


def test_get_ossec_log_fields_ko():
    """Test get_ossec_log_fields() method returns None when nothing matches."""
    result = get_ossec_log_fields('DEBUG')
    assert not result


@pytest.mark.parametrize('log_format', [LoggingFormat.plain, LoggingFormat.json])
def test_get_ossec_logs(log_format):
    """Test get_ossec_logs() method returns result with expected information."""
    logs = get_logs(json_log=log_format == LoggingFormat.json).splitlines()

    with pytest.raises(WazuhInternalError, match='.*1000.*'):
        get_ossec_logs()

    with patch('wazuh.core.manager.exists', return_value=True):
        with patch('wazuh.core.manager.tail', return_value=logs):
            result = get_ossec_logs()
            assert all(key in log for key in ('timestamp', 'tag', 'level', 'description') for log in result)


@patch('wazuh.core.manager.exists', return_value=True)
def test_get_logs_summary(mock_exists):
    """Test get_logs_summary() method returns result with expected information."""
    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_logs_summary()
        assert all(
            key in log for key in ('all', 'info', 'error', 'critical', 'warning', 'debug') for log in result.values()
        )
        assert result['wazuh-modulesd:database'] == {
            'all': 2,
            'info': 0,
            'error': 0,
            'critical': 0,
            'warning': 0,
            'debug': 2,
        }


@patch('wazuh.core.manager.exists', return_value=True)
def test_validation_ko(mock_exists):
    """Test validate_ossec_conf raises an error."""
    # Socket creation raise socket.error
    with patch('socket.socket', side_effect=socket.error):
        with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
            validate_ossec_conf()

    with patch('socket.socket.bind'):
        # Socket connection raise socket.error
        with patch('socket.socket.connect', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                validate_ossec_conf()

        # execq_socket_path not exists
        with patch('wazuh.core.manager.exists', return_value=False):
            with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                validate_ossec_conf()

        with patch('socket.socket.connect'):
            # Socket send raise socket.error
            with patch('wazuh.core.manager.WazuhSocket.send', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                    validate_ossec_conf()

            with patch('socket.socket.send'):
                # Socket recv raise socket.error
                with patch('wazuh.core.manager.WazuhSocket.receive', side_effect=socket.timeout):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        validate_ossec_conf()

                # _parse_execd_output raise KeyError
                with patch('wazuh.core.manager.WazuhSocket'):
                    with patch('wazuh.core.manager.parse_execd_output', side_effect=KeyError):
                        with pytest.raises(WazuhInternalError, match='.* 1904 .*'):
                            validate_ossec_conf()


@pytest.mark.parametrize(
    'error_flag, error_msg',
    [
        (0, ''),
        (
            1,
            '2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: '
            'Unspecified key',
        ),
        (
            1,
            '2019/02/27 11:30:24 wazuh-authd: ERROR: (1230): Invalid element in the configuration: '
            "'use_source_i'.\n2019/02/27 11:30:24 wazuh-authd: ERROR: (1202): Configuration error at "
            "'/var/ossec/etc/ossec.conf'.",
        ),
    ],
)
def test_parse_execd_output(error_flag, error_msg):
    """Test parse_execd_output function works and returns expected message.

    Parameters
    ----------
    error_flag : int
        Indicate if there is an error found.
    error_msg
        Error message to be sent.
    """
    json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
    if not error_flag:
        result = parse_execd_output(json_response)
        assert result['status'] == 'OK'
    else:
        with pytest.raises(WazuhException, match='.* 1908 .*'):
            parse_execd_output(json_response)


@pytest.mark.parametrize('update_check', (True, False))
@pytest.mark.parametrize('last_check_date', (None, datetime.now()))
def test_get_update_information_template(last_check_date, update_check, installation_uid):
    """Test that the get_update_information_template function is working properly with the given data."""
    template = get_update_information_template(
        uuid=installation_uid, update_check=update_check, last_check_date=last_check_date
    )

    assert 'uuid' in template
    assert 'last_check_date' in template
    assert template['last_check_date'] == (last_check_date if last_check_date is not None else '')
    assert 'update_check' in template
    assert template['update_check'] == update_check
    assert 'current_version' in template
    assert template['current_version'] == f'v{wazuh.__version__}'
    assert 'last_available_major' in template
    assert 'last_available_minor' in template
    assert 'last_available_patch' in template


@pytest.mark.asyncio
async def test_query_update_check_service_timeout(installation_uid):
    """Test that the query_update_check_service function calls httpx.AsyncClient with a timeout."""
    with patch('httpx.AsyncClient') as client:
        await query_update_check_service(installation_uid)

        client.assert_called_with(verify=ANY, timeout=httpx.Timeout(DEFAULT_TIMEOUT))


@pytest.mark.asyncio
async def test_query_update_check_service_catch_exceptions_and_dont_raise(installation_uid, client_session_get_mock):
    """Test that the query_update_check_service function handle errors correctly."""
    message_error = 'Some client error'
    client_session_get_mock.side_effect = httpx.RequestError(message_error)
    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == 500
    assert update_information['message'] == message_error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'major,minor,patch',
    (
        [['5.0.0', '5.0.1'], ['4.9.0', '4.9.1'], ['4.8.1', '4.8.2']],
        [
            ['5.0.0', '5.0.1'],
            ['4.9.0', '4.9.1'],
            [
                '4.8.1',
            ],
        ],
        [['5.0.0', '5.0.1'], ['4.9.0'], ['4.8.1', '4.8.2']],
        [['5.0.0'], ['4.9.1'], ['4.8.1']],
        [['5.0.0'], ['4.9.1'], []],
        [['5.0.0'], [], ['4.8.1']],
        [[], ['4.9.1'], ['4.8.1']],
        [[], [], []],
    ),
)
async def test_query_update_check_service_returns_correct_data_when_status_200(
    installation_uid, client_session_get_mock, major, minor, patch
):
    """Test that query_update_check_service function proccess the updates information correctly."""

    def _build_release_info(semvers: list[str]) -> list:
        release_info = []
        for semver in semvers:
            major, minor, patch = semver.split('.')
            release_info.append(
                {
                    'tag': f'v{semver}',
                    'description': 'Some description',
                    'title': f'Wazuh {semver}',
                    'published_date': '2023-09-22T10:44:00Z',
                    'semver': {'minor': minor, 'patch': patch, 'major': major},
                }
            )

        return release_info

    response_data = {
        'data': {
            'minor': _build_release_info(minor),
            'patch': _build_release_info(patch),
            'major': _build_release_info(major),
        }
    }
    status = 200

    client_session_get_mock.return_value = httpx.Response(status_code=status, json=response_data)

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status
    assert update_information['uuid'] == installation_uid

    if len(major):
        assert update_information['last_available_major'] == response_data['data']['major'][-1]
    else:
        assert update_information['last_available_major'] == {}

    if len(minor):
        assert update_information['last_available_minor'] == response_data['data']['minor'][-1]
    else:
        assert update_information['last_available_minor'] == {}

    if len(patch):
        assert update_information['last_available_patch'] == response_data['data']['patch'][-1]
    else:
        assert update_information['last_available_patch'] == {}


@pytest.mark.asyncio
async def test_query_update_check_service_returns_correct_data_on_error(installation_uid, client_session_get_mock):
    """Test that query_update_check_service function returns correct data when an error occurs."""
    response_data = {'errors': {'detail': 'Unauthorized'}}
    status = 403

    client_session_get_mock.return_value = httpx.Response(status_code=status, json=response_data)

    update_information = await query_update_check_service(installation_uid)

    client_session_get_mock.assert_called()

    assert update_information['status_code'] == status
    assert update_information['message'] == response_data['errors']['detail']


@pytest.mark.asyncio
async def test_query_update_check_service_request(installation_uid, client_session_get_mock):
    """Test that query_update_check_service function make request to the URL with the correct headers."""
    version = '4.8.0'

    with patch.object(CentralizedConfig, 'load', return_value=None):
        CentralizedConfig._config = default_config
        with patch('framework.wazuh.core.manager.wazuh.__version__', version):
            await query_update_check_service(installation_uid)

            client_session_get_mock.assert_called()

            client_session_get_mock.assert_called_with(
                RELEASE_UPDATES_URL,
                headers={
                    WAZUH_UID_KEY: installation_uid,
                    WAZUH_TAG_KEY: f'v{version}',
                    USER_AGENT_KEY: f'Wazuh UpdateCheckService/v{version}',
                },
                follow_redirects=True,
            )
