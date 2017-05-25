#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


class WazuhException(Exception):
    """
    Wazuh Exception object.
    """

    ERRORS = {
        # Wazuh: 0999 - 1099
        999: 'Incompatilbe version of Python',
        1000: 'Wazuh Internal Error',
        1001: 'Error importing module',
        1002: 'Error executing command',
        1003: 'Command output not in json',
        1004: 'Malformed command output ',
        1005: 'Error reading file',
        1006: 'File/directory does not exist',
        1010: 'Unable to connect to queue',
        1011: 'Error communicating with queue',
        1012: 'Invalid message to queue',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',
        1101: 'Error getting configuration',
        1102: 'Invalid section',
        1103: 'Invalid field in section',
        1104: 'Invalid type',

        # Rule: 1200 - 1299
        1200: 'Error reading rules from ossec.conf',
        1201: 'Error reading rule files',
        1202: 'Argument \'status\' must be: enabled, disabled or all',
        1203: 'Argument \'level\' must be a number or an interval separated by \'-\'',
        1204: 'Operation not implemented',

        # Stats: 1300 - 1399
        1307: 'Invalid parameters',
        1308: 'Stats file has not been created yet',
        1309: 'Statistics file damaged',

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: 'Invalid order. Order must be \'asc\' or \'desc\'',
        1403: 'Sort field invalid',  # Also, in DB
        1404: 'A field must be specified to order the data',

        # Decoders: 1500 - 1599
        1500: 'Error reading decoders from ossec.conf',
        1501: 'Error reading decoder files',

        # Syscheck/Rootcheck: 1600 - 1699
        1600: 'There is no database for selected agent',  # Also, agent
        1601: 'Unable to restart syscheck/rootcheck',
        1602: 'Impossible to run syscheck/run due to agent is not active',

        # Agents:
        1700: 'Bad arguments. Accepted arguments: [id] or [name and ip]',
        1701: 'Agent does not exist',
        1702: 'Unable to restart agent(s)',
        1703: 'Action not available for Manager (Agent 000)',
        1704: 'Adding/removing agents via API when ossec-authd is running is not compatible',
        1705: 'There is an agent with the same name',
        1706: 'There is an agent with the same IP',
        1707: 'Impossible to restart agent due to it is not active',
        1708: 'There is an agent with the same ID',
        1709: 'Too short key size (<64)',
        1710: 'The group does not exist',
        1711: 'The group already exists',
        1712: 'Default group is not removable',
        # Manager:

        # Database:
        2000: 'No such database file',
        2001: 'Incompatible version of SQLite',

    }

    def __init__(self, code, extra_message=None, cmd_error=False):
        """
        Creates a Wazuh Exception.

        :param code: Exception code.
        :param extra_message: Adds an extra message to the error description.
        :param cmd_error: If it is a custom error code (i.e. ossec commands), the error description will be the message.
        """
        self.code = code
        if not cmd_error:
            if extra_message:
                self.message = "{0}: {1}".format(self.ERRORS[code], extra_message)
            else:
                self.message = "{0}.".format(self.ERRORS[code])
        else:
            self.message = extra_message

    def __str__(self):
        return "Error {0} - {1}".format(self.code, self.message)
