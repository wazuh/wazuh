'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
        Created by Wazuh, Inc. <info@wazuh.com>.
        This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import subprocess
import platform

from wazuh_testing.constants.paths.binaries import AGENT_AUTH_PATH
from wazuh_testing.constants.platforms import LINUX

AGENT_AUTH_LAUNCH_TIMEOUT = 10
MANAGER_ADDRESS = '127.0.0.1'


class AgentAuthParser:
    """Creates the right invoke command to call agent-auth with all the different configurations"""
    def __init__(self, server_address=None, BINARY_PATH='/var/ossec/bin/agent-auth', sudo=False):
        self._command = []
        if sudo:
            self._command.append('sudo')
        self._command += [BINARY_PATH]
        if server_address:
            self._command += ['-m', server_address]

    def get_command(self):
        return self._command

    def add_agent_name(self, agent_name):
        self._command += ['-A', agent_name]

    def add_agent_adress(self, agent_adress):
        self._command += ['-I', agent_adress]

    def add_auto_negotiation(self):
        self._command += ['-a']

    def add_ciphers(self, ciphers):
        self._command += ['-c', ciphers]

    def add_agent_certificates(self, key, cert):
        self._command += ['-k', key, '-x', cert]

    def add_manager_ca(self, ca_cert):
        self._command += ['-v', ca_cert]

    def use_source_ip(self):
        self._command += ['-i']

    def add_password(self, password):
        self._command += ['-P', password]

    def add_groups(self, group_string):
        self._command += ['-G', group_string]


def launch_agent_auth(test_configuration):
    """Launches agent-auth based on a specific dictionary configuration

    Args:
        configuration (dict): Dictionary with the agent-auth configuration.
    """
    if test_configuration.get('manager_address'):
        parser = AgentAuthParser(server_address=test_configuration.get('manager_address'),
                                 BINARY_PATH=AGENT_AUTH_PATH,
                                 sudo=True if platform.system() == LINUX else False)
    else:
        parser = AgentAuthParser(server_address=MANAGER_ADDRESS, BINARY_PATH=AGENT_AUTH_PATH,
                                 sudo=True if platform.system() == LINUX else False)
    if test_configuration.get('agent_name'):
        parser.add_agent_name(test_configuration.get("agent_name"))
    if test_configuration.get('agent_address'):
        parser.add_agent_adress(test_configuration.get("agent_address"))
    if test_configuration.get('auto_method') == 'yes':
        parser.add_auto_negotiation()
    if test_configuration.get('ssl_cipher'):
        parser.add_ciphers(test_configuration.get('ssl_cipher'))
    if test_configuration.get('server_ca_path'):
        parser.add_manager_ca(test_configuration.get('server_ca_path'))
    if test_configuration.get('agent_key_path'):
        parser.add_agent_certificates(test_configuration.get('agent_key_path'), test_configuration.get('agent_certificate_path'))
    if test_configuration.get('use_source_ip'):
        parser.use_source_ip()
    if test_configuration.get('password'):
        parser.add_password(test_configuration.get('password'))
    if test_configuration.get('groups'):
        parser.add_groups(test_configuration.get('groups'))

    return subprocess.call(parser.get_command(), timeout=AGENT_AUTH_LAUNCH_TIMEOUT)
