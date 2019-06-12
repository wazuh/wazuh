# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict
import json
import os
import re
import yaml

from api.api_exception import APIException
from api.constants import CONFIG_FILE_PATH, UWSGI_CONFIG_PATH
from api.util import to_relative_path
from api import validator
from wazuh import common


def get_old_config() -> Dict:
    """
    Gets variables from old API
    :param old_config_path: path of old API configuration file
    :return: dict with the variables from 'config.js' file
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
    except IOError as e:
        raise APIException(2002, details=f'Error loading {to_relative_path(old_config_path)} '
                           f'file: {e.strerror}')

    return rename_old_fields(old_config)


def parse_to_yaml_value(value: str) -> [str, bool, int]:
    """
    Parses a string value to boolean or int if it is needed
    :param value: string to be parsed
    :return: parsed value
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
    :param config: dict with values of old configuration
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
    :param config: dict with values of old configuration
    :return: dict with renamed old fields
    """
    new_config = config.copy()

    # relocate nested fields
    if 'https' in new_config:
        new_config['https'] = {'enabled': new_config['https'], 'key': '',
                               'cert': '', 'ca': ''}

        if 'https_key' in new_config:
            new_config['https']['key'] = os.path.join(common.ossec_path,
                                                      'api/configuration/security/ssl',
                                                      new_config['https_key'].split('/')[-1])
            del new_config['https_key']

        if 'https_cert' in new_config:
            new_config['https']['cert'] = os.path.join(common.ossec_path,
                                                       'api/configuration/security/ssl',
                                                       new_config['https_cert'].split('/')[-1])
            del new_config['https_cert']

        if 'https_use_ca' in new_config and new_config['https_use_ca'] is True \
            and 'https_ca' in new_config:
            new_config['https']['ca'] = os.path.join(common.ossec_path,
                                                          'api/configuration/security/ssl',
                                                          new_config['https_ca'].split('/')[-1])

        # delete https_use_ca and https_ca fields
        if 'https_use_ca' in new_config:
            del new_config['https_use_ca']
        if 'https_ca' in new_config:
            del new_config['https_ca']

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


def write_api_conf(config: Dict):
    """
    Cast a dictionary into a YAML and write it into an API configuration file
    :param config: dict with new API configuration
    """
    json_config = json.dumps(config)
    try:
        with open(CONFIG_FILE_PATH, 'w') as output_file:
            yaml.dump(json.loads(json_config), output_file,
                      default_flow_style=False, allow_unicode=True)
        # change group and permissions from config.yml file
        os.chown(CONFIG_FILE_PATH, common.ossec_uid, common.ossec_gid)
        os.chmod(CONFIG_FILE_PATH, 0o640)
    except IOError as e:
        raise APIException(2002, details='API configuration could not be written into '
                           f'{to_relative_path(CONFIG_FILE_PATH)} file: '
                           f'{e.strerror}')


def write_uwsgi_conf(old_config: str, enable_https: False=bool):
    """
    Update uWSGI configuration file
    :param old_config: string with the content of old API configuration file
    :enable_https: True to enable HTTPS, False otherwise
    """
    try:
        with open(UWSGI_CONFIG_PATH, 'r') as input_file:
            content = input_file.read()
            if enable_https:
                # set https configuration
                content = re.sub(r'# shared-socket: \d\.\d\.\d\.\d:\d{1,5}',
                                 f"shared-socket: {old_config['host']}:{old_config['port']}",
                                 content)
                # enable CA if it is enabled in old API
                if old_config['https']['ca']:
                    content = re.sub(r'# https: =\d{1,5},\w*\.crt,\w*\.key,\w* #,\w*\.crt',
                                    f"https: =0,{old_config['https']['cert']},{old_config['https']['key']},HIGH,"
                                    f"{old_config['https']['ca']}",
                                    content)
                else:
                    content = re.sub(r'# https: =\d{1,5},\w*\.crt,\w*\.key,\w* #,\w*\.crt',
                                    f"https: =0,{old_config['https']['cert']},{old_config['https']['key']},HIGH",
                                    content)
                # disable http connexion
                content = re.sub(r'http: \d\.\d\.\d\.\d:\d{1,5}',
                                 '# http: 0.0.0.0:55000', content)
            else:
                content = re.sub(r'http: \d\.\d\.\d\.\d:\d{1,5}',
                                 f"http: {old_config['host']}:{old_config['port']}",
                                 content)
        with open(UWSGI_CONFIG_PATH, 'w') as output_file:
            output_file.write(content)
    except IOError as e:
        raise APIException(2002, details='API configuration could not be written into '
                           f'{to_relative_path(UWSGI_CONFIG_PATH)} file: '
                           f'{e.strerror}')


if __name__ == '__main__':
    old_config = get_old_config()
    if 'https' in old_config and 'enabled' in old_config['https'] and \
        old_config['https']['enabled'] == True:
        write_uwsgi_conf(old_config, enable_https=True)
    else:
        write_uwsgi_conf(old_config, enable_https=False)
    # port and host fields are configured on uWSGI configuration file in new API
    del old_config['host']
    del old_config['port']
    # https field should be deleted in new API configuration if it exists
    if 'https' in old_config:
        del old_config['https']
    write_api_conf(old_config)
