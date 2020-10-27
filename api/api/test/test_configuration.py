# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
from unittest.mock import patch

import pytest

from api import configuration, api_exception
from wazuh.core import common

custom_api_configuration = {
    "host": "127.0.1.1",
    "port": 1000,
    "behind_proxy_server": False,
    "https": {
        "enabled": True,
        "key": "api/configuration/ssl/server.key",
        "cert": "api/configuration/ssl/server.crt",
        "use_ca": False,
        "ca": "api/configuration/ssl/ca.crt"
    },
    "logs": {
        "level": "DEBUG",
        "path": "/api/logs/wazuhapi.log"
    },
    "cors": {
        "enabled": True,
        "source_route": "*",
        "expose_headers": "*",
        "allow_headers": "*",
        "allow_credentials": False,
    },
    "cache": {
        "enabled": True,
        "time": 5
    },
    "use_only_authd": False,
    "drop_privileges": True,
    "experimental_features": False
}

custom_incomplete_configuration = {
    "logs": {
        "level": "DEBUG"
    },
    "use_only_authd": True
}


def check_config_values(config, read_config, default_config):
    for k in default_config.keys() - read_config.keys():
        if isinstance(default_config[k], str):
            assert config[k] == default_config[k].lower()
        elif isinstance(default_config[k], dict):
            check_config_values(config[k], read_config.get(k, {}), default_config[k])
        else:
            assert config[k] == default_config[k]


@pytest.mark.parametrize('read_config', [
    {},
    configuration.default_api_configuration,
    custom_api_configuration,
    custom_incomplete_configuration
])
@patch('os.path.exists', return_value=True)
@patch('builtins.open')
def test_read_configuration(mock_open, mock_exists, read_config):
    """ Tests reading different API configurations."""
    with patch('api.configuration.yaml.safe_load') as m:
        m.return_value = copy.deepcopy(read_config)
        config = configuration.read_yaml_config()
        for section, subsection in [('logs', 'path'), ('https', 'key'), ('https', 'cert'), ('https', 'ca')]:
            config[section][subsection] = config[section][subsection].replace(common.ossec_path+'/', '')

        check_config_values(config, {}, read_config)

        # values not present in the read user configuration will be filled with default values
        check_config_values(config, read_config, configuration.default_api_configuration)


@patch('os.path.exists', return_value=True)
def test_read_wrong_configuration(mock_exists):
    """Verify that expected exceptions are raised when incorrect configuration"""
    with patch('api.configuration.yaml.safe_load') as m:
        with pytest.raises(api_exception.APIError, match=r'\b2004\b'):
            configuration.read_yaml_config()

        with patch('builtins.open'):
            m.return_value = {'marta': 'yay'}
            with pytest.raises(api_exception.APIError, match=r'\b2000\b'):
                configuration.read_yaml_config()


@patch('os.chmod')
@patch('builtins.open')
def test_generate_private_key(mock_open, mock_chmod):
    """Verify that genetare_private_key returns expected key and 'open' method is called with expected parameters"""
    result_key = configuration.generate_private_key('test_path.crt', 65537, 2048)

    assert result_key.key_size == 2048
    mock_open.assert_called_once_with('test_path.crt', 'wb')
    mock_chmod.assert_called_once()


@patch('os.chmod')
@patch('builtins.open')
def test_generate_self_signed_certificate(mock_open, mock_chmod):
    """Verify that genetare_private_key returns expected key and 'open' method is called with expected parameters"""
    result_key = configuration.generate_private_key('test_path.crt', 65537, 2048)
    configuration.generate_self_signed_certificate(result_key, 'test_path.crt')

    assert mock_open.call_count == 2, 'Not expected number of calls'
    assert mock_chmod.call_count == 2, 'Not expected number of calls'


