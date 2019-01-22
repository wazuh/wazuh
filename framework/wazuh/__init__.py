#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.utils import execute
from wazuh.database import Connection
from time import strftime
from wazuh.exception import WazuhException
import re


"""
Wazuh HIDS Python package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wazuh is a python package to manage OSSEC.

"""

__version__ = '3.8.0'


msg = "\n\nPython 2.7 or newer not found."
msg += "\nUpdate it or set the path to a valid version. Example:"
msg += "\n  export PATH=$PATH:/opt/rh/python27/root/usr/bin"
msg += "\n  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/rh/python27/root/usr/lib64"

try:
    from sys import version_info as python_version
    if python_version.major < 2 or (python_version.major == 2 and python_version.minor < 7 ):
        raise WazuhException(999, msg)
except Exception as e:
    raise WazuhException(999, msg)

class Wazuh:
    """
    Basic class to set up OSSEC directories
    """

    OSSEC_INIT = '/etc/ossec-init.conf'

    def __init__(self, ossec_path='/var/ossec', get_init=False):
        """
        Initialize basic information and directories.
        :param ossec_path: OSSEC Path. By default it is /var/ossec.
        :param get_init: Get information from /etc/ossec-init.conf.
        :return:
        """

        self.version = None
        self.installation_date = None
        self.type = None
        self.path = ossec_path
        self.max_agents = 'N/A'
        self.openssl_support = 'N/A'
        self.ruleset_version = None
        self.tz_offset = None
        self.tz_name = None

        if get_init:
            self.get_ossec_init()

        common.set_paths_based_on_ossec(self.path)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'path': self.path, 'version': self.version, 'compilation_date': self.installation_date, 'type': self.type, 'max_agents': self.max_agents, 'openssl_support': self.openssl_support, 'ruleset_version': self.ruleset_version, 'tz_offset': self.tz_offset, 'tz_name': self.tz_name}

    def get_ossec_init(self):
        """
        Gets information from /etc/ossec-init.conf.

        :return: ossec-init.conf as dictionary
        """

        try:
            with open(self.OSSEC_INIT, 'r') as f:
                line_regex = re.compile('(^\w+)="(.+)"')
                for line in f:
                    match = line_regex.match(line)
                    if match and len(match.groups()) == 2:
                        key = match.group(1).lower()
                        if key == "version":
                            self.version = match.group(2)
                        elif key == "directory":
                            # Read 'directory' when ossec_path (__init__) is set by default.
                            # It could mean that get_init is True and ossec_path is not used.
                            if self.path == '/var/ossec':
                                self.path = match.group(2)
                                common.set_paths_based_on_ossec(self.path)
                        elif key == "date":
                            self.installation_date = match.group(2)
                        elif key == "type":
                            if (str(match.group(2)) == "server"):
                                self.type = "manager"
                            else:
                                self.type = match.group(2)
        except:
            raise WazuhException(1005, self.OSSEC_INIT)

        # info DB if possible
        try:
            conn = Connection(common.database_path_global)

            query = "SELECT * FROM info"
            conn.execute(query)

            for tuple in conn:
                if tuple[0] == 'max_agents':
                    self.max_agents = tuple[1]
                elif tuple[0] == 'openssl_support':
                    self.openssl_support = tuple[1]
        except:
            self.max_agents = "N/A"
            self.openssl_support = "N/A"

        # Ruleset version
        ruleset_version_file = "{0}/ruleset/VERSION".format(self.path)
        try:
            with open(ruleset_version_file, 'r') as f:
                line_regex = re.compile('(^\w+)="(.+)"')
                for line in f:
                    match = line_regex.match(line)
                    if match and len(match.groups()) == 2:
                        self.ruleset_version = match.group(2)
        except:
            raise WazuhException(1005, ruleset_version_file)

        # Timezone info
        try:
            self.tz_offset = strftime("%z")
            self.tz_name = strftime("%Z")
        except:
            self.tz_offset = None
            self.tz_name = None

        return self.to_dict()


def main():
    print("Wazuh HIDS Library")
