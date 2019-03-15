# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict
import json
import os
import re
import yaml

from api.api_exception import APIException
from wazuh import common

from api import validator


def get_old_config() -> Dict:
    """
    Gets variables from old API
    :param old_config_path: Path of old API configuration file
    :return: Dictionary with the variables from 'config.js' file
    """
    old_config_path = os.path.join(common.ossec_path, '~api/configuration/config.js')
    old_config = {}
    regex = re.compile(r'^\s*config.(\w+)\s*=\s*\"?([\w\/.]*|true|false)\"?;?$')
    try:
        # import old config file!
        with open(old_config_path) as input_file:
            for line in input_file:
                match = regex.match(line)
                if match:
                    var_name, var_value = match.groups()
                    if check_old_config({var_name: var_value}):
                        # add element to old_config only if it is right
                        old_config[var_name] = parse_to_yaml_value(var_value)
    except IOError:
        raise APIException(2002)

    return rename_old_fields(old_config)


def parse_to_yaml_value(value: str) -> [str, bool, int]:
    """
    Parses a string value to boolean or int if it is needed
    :param value: String to be parsed
    :return: Parsed value
    """
    if value in ('yes', 'true'):
        return True
    elif value in ('no', 'false'):
        return False
    else:
        # if str contains an integer, returns as integer
        return int(value) if value.isdigit() else value


def check_old_config(config: Dict) -> bool:
    """
    Checks if old configuration is OK
    :param config: Dictionary with values of old configuration
    :return: True if old configuration is OK, False otherwise
    """
    checks = {'host': validator._ips,
              'port': validator._numbers,
              'basic_auth': validator._yes_no_boolean,
              'BehindProxyServer': validator._yes_no_boolean,
              'https': validator._yes_no_boolean,
              'https_key': validator._paths,
              'https_cert': validator._paths,
              'logs': validator._names,
              'cors': validator._yes_no_boolean,
              'cache_enabled': validator._yes_no_boolean,
              'cache_debug': validator._yes_no_boolean,
              'cache_time': validator._numbers,
              'use_only_authd': validator._boolean,
              'drop_privileges': validator._boolean,
              'experimental_features': validator._boolean
             }

    # check old configuration values
    for key, value in config.items():
        if key not in checks or not validator.check_exp(value, checks[key]):
            return False

    return True


def rename_old_fields(config: Dict) -> Dict:
    """
    Renames the name of old configuration fields to the current format
    :param config: Dictionary with values of old configuration
    :return: Dictionary with renamed old fields
    """
    new_config = config.copy()

    # relocate nested fields
    if 'https' in new_config:
        new_config['https'] = {'enabled': new_config['https'], 'key': '',
                               'cert': ''}

        if 'https_key' in new_config:
            new_config['https']['key'] = os.path.join('api', new_config['https_key'])
            del new_config['https_key']

        if 'https_cert' in new_config:
            new_config['https']['cert'] = os.path.join('api', new_config['https_cert'])
            del new_config['https_cert']

    if 'logs' in new_config:
        new_config['logs'] = {'level': new_config['logs']}

    new_config['cache'] = {'enabled': True, 'debug': 'info', 'time': 750}

    if 'cache_enabled' in new_config:
        new_config['cache']['enabled'] = new_config['cache_enabled']
        del new_config['cache_enabled']

    if 'cache_debug' in new_config:
        new_config['cache']['debug'] = new_config['cache_debug']
        del new_config['cache_debug']

    if 'cache_time' in new_config:
        new_config['cache']['time'] = new_config['cache_time']
        del new_config['cache_time']

    # fields to be renamed
    old_to_new = {'BehindProxyServer': 'behind_proxy_server'}
    # allowed fields
    allowed_fields = ('host', 'port', 'basic_auth', 'BehindProxyServer',
                      'https', 'https_key', 'https_cert', 'logs', 'cors',
                      'cache_enabled', 'cache_debug', 'cache_time',
                      'use_only_authd', 'drop_privileges', 'experimental_features')
    # delete and rename old fields
    for key in config:
        if key in old_to_new:
            new_config[old_to_new[key]] = config[key]
            del new_config[key]
        if key not in allowed_fields:
            del new_config[key]

    return new_config


def write_into_yaml_file(config: Dict):
    """
    Writes old configuration into a YAML file
    :param config: Dictionary with old configuration values
    """
    json_config = json.dumps(config)
    try:
        with open(common.api_config_path, 'w') as output_file:
            yaml.dump(json.loads(json_config), output_file, default_flow_style=False, allow_unicode=True)
        # change group and permissions from config.yml file
        os.chown(common.api_config_path, common.ossec_uid, common.ossec_gid)
        os.chmod(common.api_config_path, 0o640)
    except IOError:
        raise APIException(2002)


if __name__ == '__main__':
    write_into_yaml_file(get_old_config())
