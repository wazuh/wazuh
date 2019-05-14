#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import ipaddress
from api.constants import UWSGI_CONFIG_PATH, API_CONFIG_PATH, TEMPLATE_API_CONFIG_PATH
import re

_ip_host = re.compile(r'http:(.*):')
_proxy_value = re.compile(r'(.*)behind_proxy_server:(.*)')
_basic_auth_value = re.compile(r'(.*)basic_auth:(.*)')

new_api_yaml = False


def check_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print('[FAIL] Address/Netmask is invalid: {}'.format(ip))
    except Exception:
        print('[FAIL] There is a problem with the IP provided: {}'.format(ip))

    return False


def check_port(port):
    if port is not None:
        if 1 <= port <= 65535:
            return True
        print('[FAIL] The port provided is invalid, the port must be a number between 1 and 65535')
    return False


def check_boolean(component, value):
    if value is not None:
        if (value.lower() == 'true' or value.lower() == 'yes') \
                or (value.lower() == 'false' or value.lower() == 'no'):
            return True
        print('[FAIL] Invalid value for {}: {}'.format(component, value))
    return False


def convert_boolean_to_string(value):
    if value.lower() == 'true' or value.lower() == 'yes':
        return 'yes'
    return 'no'


def change_ip(ip):
    with open(UWSGI_CONFIG_PATH, 'r+') as f:
        lines = f.readlines()

    new_file = ''
    for line in lines:
        match = re.search(_ip_host, line)
        if match:
            splitted = line.split(':')
            new_file += splitted[0] + ': ' + ip + ':' + splitted[2]
        else:
            new_file += line
    if new_file != '':
        with open(UWSGI_CONFIG_PATH, 'w') as f:
            f.write(new_file)
        print('[INFO] IP changed correctly')


def change_port(port):
    with open(UWSGI_CONFIG_PATH, 'r+') as f:
        lines = f.readlines()

    new_file = ''
    for line in lines:
        match = re.search(_ip_host, line)
        if match:
            splitted = line.split(':')
            new_file += splitted[0] + ': ' + splitted[1] + ':' + str(port) + '\n'
        else:
            new_file += line
    if new_file != '':
        with open(UWSGI_CONFIG_PATH, 'w') as f:
            f.write(new_file)
        print('[INFO] PORT changed correctly')


def change_basic_auth(value):
    if new_api_yaml:
        with open(API_CONFIG_PATH, 'r+') as f:
            lines = f.readlines()
    else:
        with open(TEMPLATE_API_CONFIG_PATH, 'r+') as f:
            lines = f.readlines()

    new_file = ''
    for line in lines:
        match = re.search(_basic_auth_value, line)
        if match:
            splitted = line.split(':')
            comment = splitted[0].split('# ')
            if len(comment) > 1:
                splitted[0] = comment[1]
            new_file += splitted[0] + ': ' + value + '\n'
        else:
            new_file += line
    if new_file != '':
        with open(API_CONFIG_PATH, 'w') as f:
            f.write(new_file)
        print('[INFO] Basic auth value changed correctly')


def change_proxy(value):
    if new_api_yaml:
        with open(API_CONFIG_PATH, 'r+') as f:
            lines = f.readlines()
    else:
        with open(TEMPLATE_API_CONFIG_PATH, 'r+') as f:
            lines = f.readlines()

    new_file = ''
    for line in lines:
        match = re.search(_proxy_value, line)
        if match:
            splitted = line.split(':')
            comment = splitted[0].split('# ')
            if len(comment) > 1:
                splitted[0] = comment[1]
            new_file += splitted[0] + ': ' + value + '\n'
        else:
            new_file += line
    if new_file != '':
        with open(API_CONFIG_PATH, 'w') as f:
            f.write(new_file)
        print('[INFO] PROXY value changed correctly')


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port', help="Change port number", type=int)
    parser.add_argument('-i', '--ip', help="Change the host IP", type=str)
    parser.add_argument('-s', '--https', help="Enable https protocol (TRUE/FALSE)", type=bool)
    parser.add_argument('-b', '--basic', help="Configure basic authentication", type=str)
    parser.add_argument('-bp', '--proxy', help="Yes to run API behind a proxy", type=str)

    args = parser.parse_args()

    if check_ip(args.ip):
        change_ip(args.ip)

    if check_port(args.port):
        change_port(args.port)

    if check_boolean('proxy', args.proxy):
        proxy = convert_boolean_to_string(args.proxy)
        change_proxy(proxy)
        new_api_yaml = True

    if check_boolean('basic auth', args.basic):
        basic = convert_boolean_to_string(args.basic)
        change_basic_auth(basic)
