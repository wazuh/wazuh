#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import ipaddress
import re
import sys

from api.constants import UWSGI_CONFIG_PATH, API_CONFIG_PATH, TEMPLATE_API_CONFIG_PATH
from wazuh.user_manager import Users

_ip_host = re.compile(r'( *)(# )?http:(.*):')
_proxy_value = re.compile(r'(.*)behind_proxy_server:(.*)')
_basic_auth_value = re.compile(r'(.*)basic_auth:(.*)')
_wsgi_socket = re.compile(r'( *)(# )?shared-socket:(.*):')
_wsgi_certs = re.compile(r'https: =(.*)')

new_api_yaml = False
interactive = False


# Check that the uWSGI configuration file exists
def _check_uwsgi_config():
    try:
        with open(UWSGI_CONFIG_PATH, 'r+'):
            return True
    except FileNotFoundError:
        print('[ERROR] uWSGI configuration file does not exists: {}'.format(UWSGI_CONFIG_PATH))

    return False


# Checks that the provided IP is valid
def _check_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print('[ERROR] Address/Netmask is invalid: {}'.format(ip))
    except Exception as e:
        print('[ERROR] There is a problem with the IP provided: \n{}'.format(e))

    return False


# Checks that the provided port is valid
def _check_port(port):
    if port is not None:
        # In case the port cannot be converted to integer, it will return False
        try:
            if 1 <= int(port) <= 65535:
                return True
        except Exception:
            pass

    print('[ERROR] The port provided is invalid, the port must be a number between 1 and 65535')
    return False


# Checks that the provided component is valid (yes/true, no/false)
def _check_boolean(component, value):
    if value is not None:
        if (value.lower() == 'true' or value.lower() == 'yes') \
                or (value.lower() == 'false' or value.lower() == 'no'):
            return True
        print('[ERROR] Invalid value for {}: {}'.format(component, value))
    return False


# Unify true/false yes/no
def _convert_boolean_to_string(value):
    return 'yes' if value.lower() == 'true' or value.lower() == 'yes' else 'no'


# Change the fields that are an IP to the one specified by the user
def change_ip(ip=None):
    while ip != '':
        if interactive:
            ip = input('[INFO] Enter the IP to listen, press enter to not modify: ')
        if ip != '' and _check_ip(ip):
            with open(UWSGI_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()

            new_file = ''
            for line in lines:
                match = re.search(_ip_host, line)
                match_uwsgi = re.search(_wsgi_socket, line)
                if match or match_uwsgi:
                    match_split = line.split(': ')
                    ip_port = match_split[1].split(':')
                    ip_port[0] = ip
                    match_split[1] = ':'.join(ip_port)
                    new_file += ': '.join(match_split)
                else:
                    new_file += line
            if new_file != '':
                with open(UWSGI_CONFIG_PATH, 'w') as f:
                    f.write(new_file)
                print('[INFO] IP changed correctly to \'{}\''.format(ip))

                return True
        elif ip == '' and not interactive:
            print('[INFO] IP not modified')
            return False
    return False


# Change the fields that are a PORT to the one specified by the user
def change_port(port=None):
    while port != '':
        if interactive:
            port = input('[INFO] Enter the PORT to listen, press enter to not modify: ')
        if _check_port(port):
            with open(UWSGI_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()

            new_file = ''
            for line in lines:
                match = re.search(_ip_host, line)
                match_uwsgi = re.search(_wsgi_socket, line)
                if match or match_uwsgi:
                    match_split = line.split(':')
                    new_file += match_split[0] + ': ' + match_split[1] + ':' + str(port) + '\n'
                else:
                    new_file += line
            if new_file != '':
                with open(UWSGI_CONFIG_PATH, 'w') as f:
                    f.write(new_file)
                print('[INFO] PORT changed correctly to \'{}\''.format(port))
            return True
        if not interactive:
            return False
    return False


# Enable/Disable/Skip basic authentication
def change_basic_auth(value=None):
    while value is None or value.lower() != 's':
        if interactive:
            value = input('[INFO] Enable user authentication? [Y/n/s]: ')
            if value.lower() == '' or value.lower() == 'y' or value.lower() == 'yes':
                value = 'yes'
                user = input('[INFO] New API user: ')
                if user != '':
                    while True:
                        password = input('[INFO] New password: ')
                        check_pass = input('[INFO] Re-type new password: ')
                        if password == check_pass and password != '':
                            break
                        print('[ERROR] Password verification error: Passwords don\'t match or password is empty.')
                    print(Users.create_user(user, password))
            elif value.lower() == 'n' or value.lower() == 'no':
                value = 'no'
            else:
                return False
        try:
            with open(API_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()
        except FileNotFoundError:
            with open(TEMPLATE_API_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()

        new_file = ''
        value = _convert_boolean_to_string(value)
        for line in lines:
            match = re.search(_basic_auth_value, line)
            if match:
                match_split = line.split(':')
                comment = match_split[0].split('# ')
                if len(comment) > 1:
                    match_split[0] = comment[1]
                new_file += match_split[0] + ': ' + value + '\n'
            else:
                new_file += line
        if new_file != '':
            with open(API_CONFIG_PATH, 'w') as f:
                f.write(new_file)
                print('[INFO] Basic auth value set to \'{}\''.format(value))
                return True
        if not interactive:
            return False
    return False


# Enable/Disable/Skip behind proxy server
def change_proxy(value=None):
    while value is None or value.lower() != 's':
        if interactive:
            value = input('[INFO] Is the API running behind a proxy server? [y/N/s]: ')
            if value.lower() == 'y' or value.lower() == 'yes':
                value = 'yes'
            elif value.lower() == '' or value.lower() == 'n' or value.lower() == 'no':
                value = 'no'
            else:
                return False
        try:
            with open(API_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()
        except FileNotFoundError:
            with open(TEMPLATE_API_CONFIG_PATH, 'r+') as f:
                lines = f.readlines()

        new_file = ''
        for line in lines:
            match = re.search(_proxy_value, line)
            if match:
                match_split = line.split(':')
                comment = match_split[0].split('# ')
                if len(comment) > 1:
                    match_split[0] = comment[1]
                new_file += match_split[0] + ': ' + value + '\n'
            else:
                new_file += line
        if new_file != '':
            with open(API_CONFIG_PATH, 'w') as f:
                f.write(new_file)
            print('[INFO] PROXY value changed correctly to \'{}\''.format(value))

            return True
        if not interactive:
            return False
    return False


# Enable/Disable HTTP protocol
def change_http(line, value):
    match_split = line.split(':')
    if value == 'yes':
        comment = match_split[0].split('# ')
        if len(comment) > 1:
            match_split[0] = comment[0] + comment[1]
    elif value == 'no' and '# ' not in ''.join(match_split):
        comment = match_split[0].split('h')
        if len(comment) > 1:
            match_split[0] = comment[0] + '# h' + comment[1]

    print('[INFO] HTTP changed correctly to \'{}\''.format(value))
    return ':'.join(match_split)


# Enable/Disable HTTPS protocol
def change_https(value=None, https=True):
    while value is None or value.lower() != 's':
        with open(UWSGI_CONFIG_PATH, 'r+') as f:
            lines = f.readlines()

        if interactive:
            if https:
                value = input('[INFO] Enable HTTPS and generate SSL certificate? [Y/n/s]: ')
            if value.lower() == '' or value.lower() == 'y' or value.lower() == 'yes':
                value = 'yes'
            elif value.lower() == 'n' or value.lower() == 'no':
                value = 'no'
            else:
                return False

        value = _convert_boolean_to_string(value)
        new_file = ''
        for line in lines:
            match = re.search(_wsgi_socket, line)
            match_cert = re.search(_wsgi_certs, line)
            match_http = re.search(_ip_host, line)
            if match_http and not https:
                line = change_http(line, value)
                new_file += line
            elif https and (match or match_cert):
                match_split = line.split(':')
                if value == 'yes':
                    comment = match_split[0].split('# ')
                    if len(comment) > 1:
                        match_split[0] = comment[0] + comment[1]
                elif '# ' not in ''.join(match_split):  # If it is not already disable
                    if match:
                        # Split by shared-socket (sh)
                        comment = match_split[0].split('sh')
                        if len(comment) > 1:
                            match_split[0] = comment[0] + '# sh' + comment[1]
                    elif match_cert:
                        comment = match_split[0].split('h')
                        if len(comment) > 1:
                            match_split[0] = comment[0] + '# h' + comment[1]
                new_file += ':'.join(match_split)
            else:
                new_file += line
        if new_file != '':
            with open(UWSGI_CONFIG_PATH, 'w') as f:
                f.write(new_file)
            if https:
                print('[INFO] HTTPS changed correctly to \'{}\''.format(value))
            return True
        if not interactive:
            return False
    return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port',        help="Change port number",                          type=int)
    parser.add_argument('-i', '--ip',          help="Change the host IP",                          type=str)
    parser.add_argument('-b', '--basic',       help="Configure basic authentication (true/false)", type=str)
    parser.add_argument('-x', '--proxy',       help="Yes to run API behind a proxy",               type=str)
    parser.add_argument('-t', '--http',        help="Enable http protocol (true/false)",           type=str)
    parser.add_argument('-s', '--https',       help="Enable https protocol (true/false)",          type=str)
    parser.add_argument('-I', '--interactive', help="Enables guided configuration",                action='store_true')
    args = parser.parse_args()

    if _check_uwsgi_config() and len(sys.argv) > 1 and not args.interactive:
        if args.ip:
            change_ip(args.ip)

        if args.port:
            change_port(args.port)

        if _check_boolean('proxy', args.proxy):
            change_proxy(args.proxy)

        if _check_boolean('basic auth', args.basic):
            change_basic_auth(args.basic)

        if _check_boolean('https', args.https):
            change_https(args.https)

        if _check_boolean('http', args.http):
            if args.http.lower() == 'true' or args.http.lower() == 'yes':
                args.http = 'yes'
            elif args.http.lower() == 'false' or args.http.lower() == 'no':
                args.http = 'no'
            change_https(args.http, https=False)
    elif args.interactive or len(sys.argv) == 1:
        interactive = True
        print('[INFO] Interactive mode!')
        change_ip()
        change_port()
        change_proxy()
        change_basic_auth()
        change_https()
    else:
        print('[ERROR] Please check that your configuration is correct')
