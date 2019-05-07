# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh import common
from api.api_exception import APIException
import os
import yaml
from typing import Dict, List, Tuple


def dict_to_lowercase(mydict: Dict):
    """
    Turns all str values to lowercase. Supports nested dictionaries.
    :param mydict: Dictionary to lowercase
    :return: None (the dictionary's reference is modified)
    """
    for k, val in filter(lambda x: isinstance(x[1], str) or isinstance(x[1], dict), mydict.items()):
        if isinstance(val, dict):
            dict_to_lowercase(mydict[k])
        else:
            mydict[k] = val.lower()


def append_ossec_path(dictionary: Dict, path_fields: List[Tuple[str, str]]):
    """
    Appends ossec path to all path fields in a dictionary
    :param dictionary: dictionary to append ossec path
    :param path_fields: List of tuples containing path fields
    :return: None (the dictionary's reference is modified)
    """
    for section, subsection in path_fields:
        dictionary[section][subsection] = os.path.join(common.ossec_path, dictionary[section][subsection])


def fill_dict(default: Dict, config: Dict) -> Dict:
    """
    Fills a dictionary's missing values using default ones.
    :param default: Dictionary with default values
    :param config: Dictionary to fill
    :return: Filled dictionary
    """
    # check there aren't extra configuration values in user's configuration:
    if config.keys() - default.keys() != set():
        raise APIException(2000, details=', '.join(config.keys() - default.keys()))

    for k, val in filter(lambda x: isinstance(x[1], dict), config.items()):
        config[k] = {**default[k], **config[k]}

    return {**default, **config}


def read_api_config(config_file=common.api_config_path) -> Dict:
    """
    Reads user API configuration and merges it with the default one
    :return: API configuration
    """
    default_configuration = {
        "host": "0.0.0.0",
        "port": 55000,
        "basic_auth": True,
        "behind_proxy_server": False,
        "https": {
            "enabled": False,
            "key": "api/configuration/ssl/server.key",
            "cert": "api/configuration/ssl/server.crt",
            "use_ca": False,
            "ca": "api/configuration/ssl/ca.crt"
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

    if os.path.exists(common.api_config_path):
        try:
            with open(common.api_config_path) as f:
                configuration = yaml.safe_load(f)
        except IOError as e:
            raise APIException(2004, details=e.strerror)
    else:
        configuration = None

    # if any value is missing from user's cluster configuration, add the default one:
    if configuration is None:
        configuration = default_configuration
    else:
        dict_to_lowercase(configuration)
        configuration = fill_dict(default_configuration, configuration['wazuh-api'])

    # append ossec_path to all paths in configuration
    append_ossec_path(configuration, [('logs', 'path'), ('https', 'key'), ('https', 'cert'), ('https', 'ca')])

    return configuration
