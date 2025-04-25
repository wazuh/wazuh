# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core import configuration
        from wazuh.core.exception import WazuhError

parent_directory = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
tmp_path = 'tests/data'


def test_get_group_conf():
    """Test get_group_conf functionality."""
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.get_group_conf(group_id='noexists')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.load_wazuh_yaml', side_effect=WazuhError(1101)):
            with pytest.raises(WazuhError, match='.* 1101 .*'):
                result = configuration.get_group_conf(group_id='default')
                assert isinstance(result, dict)

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert configuration.get_group_conf(group_id='default')['total_affected_items'] == 1


@patch('wazuh.core.common.wazuh_gid')
@patch('wazuh.core.common.wazuh_uid')
@patch('builtins.open')
def test_update_group_configuration(mock_open, mock_wazuh_uid, mock_wazuh_gid):
    """Test update_group_configuration functionality."""
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.update_group_configuration('noexists', 'noexists')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.open', return_value=Exception):
            with pytest.raises(WazuhError, match='.* 1006 .*'):
                configuration.update_group_configuration('default', '')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.open'):
            configuration.update_group_configuration('default', 'key: value')


@patch('wazuh.core.common.wazuh_gid')
@patch('wazuh.core.common.wazuh_uid')
@patch('builtins.open')
def test_update_group_file(mock_open, mock_wazuh_uid, mock_wazuh_gid):
    """Test update_group_file functionality."""
    with pytest.raises(WazuhError, match='.* 1710 .*'):
        configuration.update_group_file('noexists', 'given')

    with pytest.raises(WazuhError, match='.* 1722 .*'):
        configuration.update_group_file('.invalid', '')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match='.* 1112 .*'):
            configuration.update_group_file('default', [])


@pytest.mark.parametrize(
    'update_check_value, expected',
    [
        (True, True),
        (False, False),
    ],
)
def test_update_check_is_enabled(update_check_value, expected):
    """Test that update_check_is_enabled returns the expected value based on update_check."""
    with patch('wazuh.core.config.client.CentralizedConfig.get_server_config') as mock_get_server_config:
        cti_mock = MagicMock()
        cti_mock.update_check = update_check_value
        server_config_mock = MagicMock()
        server_config_mock.cti = cti_mock
        mock_get_server_config.return_value = server_config_mock

        result = configuration.update_check_is_enabled()
        assert result == expected


@pytest.mark.parametrize(
    'error_code, expected',
    [
        (1101, None),
        (1103, None),
        (1106, True),
    ],
)
def test_update_check_is_enabled_exceptions(error_code, expected):
    """Test that update_check_is_enabled properly handles exceptions."""
    with patch('wazuh.core.config.client.CentralizedConfig.get_server_config', side_effect=WazuhError(error_code)):
        if expected is not None:
            assert configuration.update_check_is_enabled() == expected
        else:
            with pytest.raises(WazuhError, match=f'.* {error_code} .*'):
                configuration.update_check_is_enabled()


@pytest.mark.parametrize(
    'cti_url, expected',
    [
        ('https://default-cti.com', 'https://default-cti.com'),
        ('https://test-cti.com', 'https://test-cti.com'),
    ],
)
def test_get_cti_url(cti_url, expected):
    """Test that get_cti_url returns the expected URL based on configuration."""
    with patch('wazuh.core.config.client.CentralizedConfig.get_server_config') as mock_get_server_config:
        cti_mock = MagicMock()
        cti_mock.url = cti_url
        server_config_mock = MagicMock()
        server_config_mock.cti = cti_mock
        mock_get_server_config.return_value = server_config_mock

        result = configuration.get_cti_url()
        assert result == expected


@pytest.mark.parametrize(
    'error_code, expected',
    [
        (1101, None),
        (1103, None),
        (1106, configuration.DEFAULT_CTI_URL),
    ],
)
def test_get_cti_url_exceptions(error_code, expected):
    """Test that get_cti_url properly handles exceptions."""
    with patch('wazuh.core.config.client.CentralizedConfig.get_server_config', side_effect=WazuhError(error_code)):
        if expected is not None:
            assert configuration.get_cti_url() == expected
        else:
            with pytest.raises(WazuhError, match=f'.* {error_code} .*'):
                configuration.get_cti_url()
