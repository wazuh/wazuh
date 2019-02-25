# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh import common
import os
import yaml


def fill_dict(default, config):
    """
    Fills a dictionary's missing values using default ones.
    :param default: Dictionary with default values
    :param config: Dictionary to fill
    :return: Filled dictionary
    """
    for value_name in default.keys():
        if type(default[value_name]) == dict and value_name in config:
            config[value_name] = fill_dict(default[value_name], config[value_name])
        elif value_name not in config:
            config[value_name] = default[value_name]
        elif type(config[value_name]) == str:
            config[value_name] = config[value_name].lower()
    return config


def read_config():
    default_configuration = {
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

    with open(common.api_config_path) as f:
        configuration = yaml.safe_load(f)

    # if any value is missing from user's cluster configuration, add the default one:
    configuration = default_configuration if configuration is None else fill_dict(default_configuration, configuration)

    # append ossec_path to all paths in configuration
    for section, subsection in [('logs', 'path'), ('https', 'key'), ('https', 'cert')]:
        configuration[section][subsection] = os.path.join(common.ossec_path, configuration[section][subsection])

    return configuration
