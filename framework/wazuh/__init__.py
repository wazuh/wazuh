

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from time import strftime

from wazuh.core import common
from wazuh.core.wdb import WazuhDBConnection
from wazuh.core.exception import WazuhInternalError
from wazuh.core.cti import get_cti_client, CTIAuthTokenStatus

"""
Wazuh HIDS Python package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wazuh is a python package to manage OSSEC.

"""

__version__ = '5.0.0'


msg = "\n\nPython 2.7 or newer not found."
msg += "\nUpdate it or set the path to a valid version. Example:"
msg += "\n  export PATH=$PATH:/opt/rh/python27/root/usr/bin"
msg += "\n  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/rh/python27/root/usr/lib64"

try:
    from sys import version_info as python_version
    if python_version.major < 2 or (python_version.major == 2 and python_version.minor < 7):
        raise WazuhInternalError(999, msg)
except Exception as e:
    raise WazuhInternalError(999, msg)


class Wazuh:
    """
    Basic class to set up OSSEC directories
    """

    def __init__(self):
        """
        Initialize basic information and directories.
        :return:
        """
        self.version = f'v{__version__}'
        self.type = 'server'
        self.path = common.WAZUH_PATH
        self.max_agents = 'unlimited'
        self.openssl_support = 'N/A'
        self.tz_offset = None
        self.tz_name = None
        self.cti_auth_token_status = CTIAuthTokenStatus.PENDING

        self._initialize()

    def __str__(self):
        return str(self.to_dict())

    def __eq__(self, other):
        if isinstance(other, Wazuh):
            return self.to_dict() == other.to_dict()
        return False

    def to_dict(self):
        return {'path': self.path,
                'version': self.version,
                'type': self.type,
                'max_agents': self.max_agents,
                'openssl_support': self.openssl_support,
                'tz_offset': self.tz_offset,
                'tz_name': self.tz_name,
                'wazuh_cti_auth': {
                    'status': self.cti_auth_token_status.short_desc,
                    'description': self.cti_auth_token_status.long_desc
                    } 
                }

    def _initialize(self):
        """
        Calculates all Wazuh installation metadata
        """
        # info DB if possible
        try:
            wdb_conn = WazuhDBConnection()
            open_ssl = wdb_conn.execute("global sql SELECT value FROM info WHERE key = 'openssl_support'")[0]['value']
            self.openssl_support = open_ssl
        except Exception:
            self.openssl_support = "N/A"

        # Timezone info
        try:
            self.tz_offset = strftime("%z")
            self.tz_name = strftime("%Z")
        except Exception:
            self.tz_offset = None
            self.tz_name = None

        # CTI auth_token status
        try:
            with get_cti_client() as cti_client:
                self.cti_auth_token_status = cti_client.get_auth_token_status()
        except Exception:
            self.cti_auth_token_status = CTIAuthTokenStatus.PENDING

        return self.to_dict()


def main():
    print("Wazuh HIDS Library")
