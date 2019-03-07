# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict
import json
import os
import re
import yaml

from wazuh import common

from api import validator


def get_old_config(old_config_path: str = '/var/ossec/~api/configuration/config.js') -> Dict:
    """
    Gets variables from old API
    :param old_config_path: Path of old API configuration file
    :return: Dictionary with the variables from 'config.js' file
    """
    old_config = {}
    regex = re.compile(r'^\s*config.(\w+)\s*=\s*\"?([\w.]*|true|false)\"?;?$')
    try:
        # import old config file!
        with open(old_config_path) as input_file:
            for line in input_file:
                match = regex.match(line)
                if match:
                    var_name = match.group(1)
                    var_value = match.group(2)
                    ### check config element by element?
                    #if check_old_config({var_name: var_value}):
                    #    old_config[var_name] = var_value
                    old_config[var_name] = var_value
    except IOError, FileNotFoundError:
        raise

    return rename_old_fields(old_config)


def check_old_config(config: Dict) -> bool:
    """
    Checks if old configuration is OK
    :param config: Dictionary with values of old configuration
    :return: True if old configuration is OK, False otherwise
    """
    checks = {'host': 'ips', 'port': 'numbers', 'https': 'yes_no_boolean',
              'basic_auth': 'yes_no_boolean', 'BehindProxyServer': 'yes_no_boolean',
              'logs': 'names', 'cors': 'yes_no_boolean',
              'cache_enabled': 'yes_no_boolean', 'cache_debug': 'yes_no_boolean',
              'cache_time': 'numbers', 'use_only_authd': 'boolean',
              'drop_privileges': 'boolean', 'experimental_features': 'boolean',
              'secureProtocol': 'names', 'honorCipherOrder': 'boolean',
              'ciphers': 'names'
            }

    # check old configuration values
    for key in config:
        if key not in checks or not validator.check_exp(key, checks[key]):
            return False

    return True


def rename_old_fields(config: Dict) -> Dict:
    """
    Renames the name of old configuration fields to the current format
    :param config: Dictionary with values of old configuration
    :return: Dictionary with renamed old fields
    """
    old_to_new = {'BehindProxyServer': 'behind_proxy_server',
                  'honorCipherOrder': 'honor_cipher_order',
                  'secureProtocol': 'secure_protocol'}

    new_config = config
    for key in config:
        if key in old_to_new:
            new_config[old_to_new[key]] = config[key]
            del new_config[key]

    # relocate nested fields
    if 'https' in new_config:
        new_config['https'] = {'enabled': new_config['https'],
                               'key': '', 'cert': ''}
        if 'https_key' in new_config:
            new_config['https']['https_key'] = new_config['https_key']
            del new_config['https_key']

        if 'https_cert' in new_config:
            new_config['https']['https_cert'] = new_config['https_cert']
            del new_config['https_cert']

    if 'logs' in new_config:
        new_config['logs'] = {'level': new_config['logs']}

    new_config['cache'] = {'enabled': '', 'debug': '', 'time': ''}

    if 'cache_enabled' in new_config:
        new_config['cache']['enabled'] = new_config['cache_enabled']
        del new_config['cache_enabled']

    if 'cache_debug' in new_config:
        new_config['cache']['debug'] = new_config['cache_debug']
        del new_config['cache_debug']

    if 'cache_time' in new_config:
        new_config['cache']['time'] = new_config['cache_time']
        del new_config['cache_time']

    return new_config


def write_into_yaml_file(config: Dict):
    """
    Writes old configuration into a YAML file
    :param config: Dictionary with old configuration values
    """
    json_config = json.dumps(config)
    try:
        #with open(common.api_config_path, 'w') as output_file:
        with open('/var/ossec/api/configuration/config.yml', 'w') as output_file:
            yaml.dump(json.loads(json_config), output_file, default_flow_style=False, allow_unicode=True)
    except IOError, FileNotFoundError:
        raise


if __name__ == '__main__':
    write_into_yaml_file(get_old_config())
