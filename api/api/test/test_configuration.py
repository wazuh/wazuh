# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
from unittest.mock import patch

import pytest

from api import configuration, api_exception
from wazuh import common

# Valid configurations
default_api_configuration = {
    "host": "0.0.0.0",
    "port": 55000,
    "basic_auth": True,
    "behind_proxy_server": False,
    "https": {
        "enabled": False,
        "key": "api/configuration/ssl/server.key",
        "cert": "api/configuration/ssl/server.crt"
    },
    "logs": {
        "level": "info",
        "path": "logs/api.log"
    },
    "cors": True,
    "cache": {
        "enabled": True,
        "debug": False,
        "time": 750
    },
    "use_only_authd": False,
    "drop_privileges": True,
    "experimental_features": False
}

custom_api_configuration = {
    "host": "127.0.1.1",
    "port": 1000,
    "basic_auth": True,
    "behind_proxy_server": False,
    "https": {
        "enabled": False,
        "key": "api/configuration/ssl/server.key",
        "cert": "api/configuration/ssl/server.crt"
    },
    "logs": {
        "level": "DEBUG",
        "path": "/api/logs/wazuhapi.log"
    },
    "cors": False,
    "cache": {
        "enabled": True,
        "debug": False,
        "time": 750
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
    default_api_configuration,
    custom_api_configuration,
    custom_incomplete_configuration
])
def test_read_configuration(read_config):
    """
    Tests reading an empty API configuration.
    """
    with patch('api.configuration.yaml.safe_load') as m:
        m.return_value = copy.deepcopy(read_config)
        config = configuration.read_api_config()
        for section, subsection in [('logs', 'path'), ('https', 'key'), ('https', 'cert')]:
            config[section][subsection] = config[section][subsection].replace(common.ossec_path+'/', '')

        check_config_values(config, {}, read_config)

        # values not present in the read user configuration will be filled with default values
        check_config_values(config, read_config, default_api_configuration)


@pytest.mark.parametrize('read_config', [
    {'marta': 'yay'}
])
def test_read_wrong_configuration(read_config):
    with patch('api.configuration.yaml.safe_load') as m:
        m.return_value = copy.deepcopy(read_config)
        with pytest.raises(api_exception.APIException, match='.* 2000 .*'):
            configuration.read_api_config()
