#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from operator import mul
from functools import reduce
from wazuh import common
from wazuh.exception import WazuhException

class InputValidator:
    """
    Class to do Input Validation
    """

    def check_name(self, name, regex_str="\w+"):
        regex = re.compile(regex_str)
        matching = regex.match(name)
        if matching:
            return matching.group() == name
        else: 
            return False

    def check_length(self, name, length=100):
        return len(name) < length

    def group(self, group_name):
        """
        function to validate the name of a group. Returns True if the
        input name is valid and False otherwise

        group_name: name of the group to be validated
        """
        def check_single_group_name(group_name):
            return self.check_length(group_name) and self.check_name(group_name)

        if isinstance(group_name, list):
            return reduce(mul, map(lambda x: check_single_group_name(x), group_name))
        else:
            return check_single_group_name(group_name)

    def check_cluster_cmd(self, cmd):
        # cmd must be a list
        if not isinstance(cmd, list):
            return False

        # check command type
        if not cmd[0] in ['zip', 'node']:
            return False

        # check cmd len list
        if len(cmd) != 2:
            return False

        # check cmd len
        if len(' '.join(cmd)) != common.cluster_protocol_plain_size:
            return False

        # second argument of zip is a number
        if cmd[0] == 'zip' and not re.compile('\d+').match(cmd[1]):
            return False

        return True

    def check_cluster_config(self, config):
        if config['key'] == None:
            raise WazuhException(3004, 'Unspecified key')

        if config['node_type'] != 'master' and config['node_type'] != 'slave':
            raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and slave'.format(config['node_type']))
        if not re.compile("\d+[m|s]").match(config['interval']):
            raise WazuhException(3004, 'Invalid interval specification. Please, specify it with format <number>s or <number>m')
        if config['nodes'][0] == 'localhost' and len(config['nodes']) == 1:
            raise WazuhException(3004, 'Please specify IPs of all cluster nodes')
