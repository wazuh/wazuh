# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import ANY, MagicMock, mock_open, patch

import pytest
from wazuh.core.common import REMOTED_SOCKET

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core import configuration
        from wazuh.core.exception import WazuhError, WazuhInternalError

parent_directory = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
tmp_path = 'tests/data'


def test_get_group_conf():
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.get_group_conf(group_id='noexists')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.load_wazuh_yaml', side_effect=WazuhError(1101)):
            with pytest.raises(WazuhError, match='.* 1101 .*'):
                result = configuration.get_group_conf(group_id='default')
                assert isinstance(result, dict)

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert configuration.get_group_conf(group_id='default')['total_affected_items'] == 1


@patch('wazuh.core.configuration.common.wazuh_gid')
@patch('wazuh.core.configuration.common.wazuh_uid')
@patch('builtins.open')
def test_update_group_configuration(mock_open, mock_wazuh_uid, mock_wazuh_gid):
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.update_group_configuration('noexists', 'noexists')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.open', return_value=Exception):
            with pytest.raises(WazuhError, match='.* 1006 .*'):
                configuration.update_group_configuration('default', '')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.open'):
            configuration.update_group_configuration('default', 'key: value')


@patch('wazuh.core.configuration.common.wazuh_gid')
@patch('wazuh.core.configuration.common.wazuh_uid')
@patch('builtins.open')
def test_update_group_file(mock_open, mock_wazuh_uid, mock_wazuh_gid):
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.update_group_file('noexists', 'given')

    with pytest.raises(WazuhError, match='.* 1722 .*'):
        configuration.update_group_file('.invalid', '')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match='.* 1112 .*'):
            configuration.update_group_file('default', [])


@pytest.mark.parametrize(
    'agent_id, component, socket, socket_dir, rec_msg',
    [
        (None, 'auth', 'auth', 'sockets', 'ok {"auth": {"use_password": "yes"}}'),
        (None, 'auth', 'auth', 'sockets', 'ok {"auth": {"use_password": "no"}}'),
        (None, 'auth', 'auth', 'sockets', 'ok {"auth": {}}'),
        (None, 'agent', 'analysis', 'sockets', {'error': 0, 'data': {'enabled': 'yes'}}),
        (None, 'agentless', 'agentless', 'sockets', 'ok {"agentless": {"enabled": "yes"}}'),
        (None, 'analysis', 'analysis', 'sockets', {'error': 0, 'data': {'enabled': 'yes'}}),
        (None, 'com', 'com', 'sockets', 'ok {"com": {"enabled": "yes"}}'),
        (None, 'csyslog', 'csyslog', 'sockets', 'ok {"csyslog": {"enabled": "yes"}}'),
        (None, 'integrator', 'integrator', 'sockets', 'ok {"integrator": {"enabled": "yes"}}'),
        (None, 'logcollector', 'logcollector', 'sockets', 'ok {"logcollector": {"enabled": "yes"}}'),
        (None, 'mail', 'mail', 'sockets', 'ok {"mail": {"enabled": "yes"}}'),
        (None, 'monitor', 'monitor', 'sockets', 'ok {"monitor": {"enabled": "yes"}}'),
        (None, 'request', 'remote', 'sockets', {'error': 0, 'data': {'enabled': 'yes'}}),
        (None, 'syscheck', 'syscheck', 'sockets', 'ok {"syscheck": {"enabled": "yes"}}'),
        (None, 'wazuh-db', 'wdb', 'db', {'error': 0, 'data': {'enabled': 'yes'}}),
        (None, 'wmodules', 'wmodules', 'sockets', 'ok {"wmodules": {"enabled": "yes"}}'),
        ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {"use_password": "yes"}}'),
        ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {"use_password": "no"}}'),
        ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {}}'),
        ('001', 'agent', 'remote', 'sockets', 'ok {"agent": {"enabled": "yes"}}'),
        ('001', 'agentless', 'remote', 'sockets', 'ok {"agentless": {"enabled": "yes"}}'),
        ('001', 'analysis', 'remote', 'sockets', 'ok {"analysis": {"enabled": "yes"}}'),
        ('001', 'com', 'remote', 'sockets', 'ok {"com": {"enabled": "yes"}}'),
        ('001', 'csyslog', 'remote', 'sockets', 'ok {"csyslog": {"enabled": "yes"}}'),
        ('001', 'integrator', 'remote', 'sockets', 'ok {"integrator": {"enabled": "yes"}}'),
        ('001', 'logcollector', 'remote', 'sockets', 'ok {"logcollector": {"enabled": "yes"}}'),
        ('001', 'mail', 'remote', 'sockets', 'ok {"mail": {"enabled": "yes"}}'),
        ('001', 'monitor', 'remote', 'sockets', 'ok {"monitor": {"enabled": "yes"}}'),
        ('001', 'request', 'remote', 'sockets', 'ok {"request": {"enabled": "yes"}}'),
        ('001', 'syscheck', 'remote', 'sockets', 'ok {"syscheck": {"enabled": "yes"}}'),
        ('001', 'wmodules', 'remote', 'sockets', 'ok {"wmodules": {"enabled": "yes"}}'),
    ],
)
@patch('builtins.open', mock_open(read_data='test_password'))
@patch('wazuh.core.wazuh_socket.create_wazuh_socket_message')
@patch('os.path.exists')
@patch('wazuh.core.common.WAZUH_PATH', new='/var/ossec')
@pytest.mark.xfail(reason='This module it is deprecated.', run=False)
def test_get_active_configuration(
    mock_exists, mock_create_wazuh_socket_message, agent_id, component, socket, socket_dir, rec_msg
):
    """This test checks the proper working of get_active_configuration function."""
    sockets_json_protocol = {'remote', 'analysis', 'wdb'}
    config = MagicMock()

    socket_class = 'WazuhSocket' if socket not in sockets_json_protocol or agent_id else 'WazuhSocketJSON'
    with patch(f'wazuh.core.wazuh_socket.{socket_class}.close') as mock_close:
        with patch(f'wazuh.core.wazuh_socket.{socket_class}.send') as mock_send:
            with patch(f'wazuh.core.wazuh_socket.{socket_class}.__init__', return_value=None) as mock__init__:
                with patch(
                    f'wazuh.core.wazuh_socket.{socket_class}.receive',
                    return_value=rec_msg.encode() if socket_class == 'WazuhSocket' else rec_msg,
                ) as mock_receive:
                    result = configuration.get_active_configuration(component, config, agent_id)

                    mock__init__.assert_called_with(
                        f'/var/ossec/queue/{socket_dir}/{socket}' if not agent_id else REMOTED_SOCKET
                    )

                    if socket_class == 'WazuhSocket':
                        mock_send.assert_called_with(
                            f'getconfig {config}'.encode()
                            if not agent_id
                            else f'{agent_id} {component} getconfig {config}'.encode()
                        )
                    else:  # socket_class == "WazuhSocketJSON"
                        mock_create_wazuh_socket_message.assert_called_with(
                            origin={'module': ANY}, command='getconfig', parameters={'section': config}
                        )
                        mock_send.assert_called_with(mock_create_wazuh_socket_message.return_value)

                    mock_receive.assert_called_once()
                    mock_close.assert_called_once()

                    if result.get('auth', {}).get('use_password') == 'yes':
                        assert result.get('authd.pass') == 'test_password'
                    else:
                        assert 'authd.pass' not in result


@pytest.mark.parametrize(
    'agent_id, component, config, socket_exist, socket_class, expected_error, expected_id',
    [
        # Checks for the manager or any other agent
        (None, 'test_component', None, ANY, 'WazuhSocket', WazuhError, 1307),  # No configuration
        (None, None, 'test_config', ANY, 'WazuhSocket', WazuhError, 1307),  # No component
        (None, 'test_component', 'test_config', ANY, 'WazuhSocket', WazuhError, 1101),  # Component not in components
        ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhError, 1116),  # Cannot send request
        ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhError, 1117),  # No such file or directory
        # Checks for manager - Simple messages
        (None, 'syscheck', 'syscheck', False, 'WazuhSocket', WazuhError, 1121),  # Socket does not exist
        (None, 'syscheck', 'syscheck', True, 'WazuhSocket', WazuhInternalError, 1121),  # Error connecting with socket
        (None, 'syscheck', 'syscheck', True, 'WazuhSocket', WazuhInternalError, 1118),  # Data could not be received
        # Checks for manager - JSON messages
        (None, 'request', 'global', False, 'WazuhSocketJSON', WazuhError, 1121),  # Socket does not exist
        (None, 'request', 'global', True, 'WazuhSocketJSON', WazuhInternalError, 1121),  # Error connecting with socket
        (None, 'request', 'global', True, 'WazuhSocketJSON', WazuhInternalError, 1118),  # Data could not be received
        # Checks for 001
        ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhInternalError, 1121),  # Error connecting with socket
        ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhInternalError, 1118),  # Data could not be received
    ],
)
@patch('os.path.exists')
def test_get_active_configuration_ko(
    mock_exists, agent_id, component, config, socket_exist, socket_class, expected_error, expected_id
):
    """Test all raised exceptions"""
    mock_exists.return_value = socket_exist
    with patch(
        f'wazuh.core.wazuh_socket.{socket_class}.__init__',
        return_value=MagicMock() if expected_id == 1121 and socket_exist else None,
    ):
        with patch(f'wazuh.core.wazuh_socket.{socket_class}.send'):
            with patch(
                f'wazuh.core.wazuh_socket.{socket_class}.receive',
                side_effect=ValueError if expected_id == 1118 else None,
                return_value=b'test 1' if expected_id == 1116 else b'test No such file or directory',
            ):
                with patch(f'wazuh.core.wazuh_socket.{socket_class}.close'):
                    with pytest.raises(expected_error, match=f'.* {expected_id} .*'):
                        configuration.get_active_configuration(component, config, agent_id)


@pytest.mark.parametrize(
    'update_check_config,expected',
    (
        [{configuration.GLOBAL_KEY: {configuration.UPDATE_CHECK_OSSEC_FIELD: 'yes'}}, True],
        [{configuration.GLOBAL_KEY: {configuration.UPDATE_CHECK_OSSEC_FIELD: 'no'}}, False],
        [{configuration.GLOBAL_KEY: {}}, True],
        [{}, True],
        [{'ossec_config': {}}, True],
    ),
)
@patch('wazuh.core.configuration.get_ossec_conf')
def test_update_check_is_enabled(get_ossec_conf_mock, update_check_config, expected):
    """Test that update_check_is_enabled function returns the expected value,
    based on the value of UPDATE_CHECK_OSSEC_FIELD.
    """
    get_ossec_conf_mock.return_value = update_check_config

    assert configuration.update_check_is_enabled() == expected


@pytest.mark.parametrize('error_id, value', [(1101, None), (1103, None), (1106, True)])
def test_update_check_is_enabled_exceptions(error_id, value):
    """Test update_check_is_enabled exception handling."""
    with patch('wazuh.core.configuration.get_ossec_conf', side_effect=WazuhError(error_id), return_value=value):
        if value is not None:
            assert configuration.update_check_is_enabled() == value
        else:
            with pytest.raises(WazuhError, match=f'.* {error_id} .*'):
                configuration.update_check_is_enabled()


@pytest.mark.parametrize(
    'config, expected',
    (
        [
            {configuration.GLOBAL_KEY: {configuration.CTI_URL_FIELD: configuration.DEFAULT_CTI_URL}},
            configuration.DEFAULT_CTI_URL,
        ],
        [{configuration.GLOBAL_KEY: {configuration.CTI_URL_FIELD: 'https://test-cti.com'}}, 'https://test-cti.com'],
        [{configuration.GLOBAL_KEY: {}}, configuration.DEFAULT_CTI_URL],
        [{}, configuration.DEFAULT_CTI_URL],
        [{'ossec_config': {}}, configuration.DEFAULT_CTI_URL],
    ),
)
@patch('wazuh.core.configuration.get_ossec_conf')
def test_get_cti_url(get_ossec_conf_mock, config, expected):
    """Check that get_cti_url function returns the expected value, based on the CTI_URL_FIELD."""
    get_ossec_conf_mock.return_value = config

    assert configuration.get_cti_url() == expected


@pytest.mark.parametrize('error_id, value', [(1101, None), (1103, None), (1106, configuration.DEFAULT_CTI_URL)])
def test_get_cti_url_exceptions(error_id, value):
    """Test get_cti_url exception handling."""
    with patch('wazuh.core.configuration.get_ossec_conf', side_effect=WazuhError(error_id), return_value=value):
        if value is not None:
            assert configuration.get_cti_url() == value
        else:
            with pytest.raises(WazuhError, match=f'.* {error_id} .*'):
                configuration.get_cti_url()
