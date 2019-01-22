#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


class WazuhException(Exception):
    """
    Wazuh Exception object.
    """

    ERRORS = {
        # < 1000: API

        # Wazuh: 0999 - 1099
        999: 'Incompatible version of Python',
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
        1013: 'Unable to connect with socket',
        1014: 'Error communicating with socket',
        1015: 'Error agent version is null. Was the agent ever connected?',
        1016: 'Error moving file',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',
        1101: 'Error getting configuration',
        1102: 'Invalid section',
        1103: 'Invalid field in section',
        1104: 'Invalid type',
        1105: 'Error reading API configuration',
        1106: 'Requested section not present in configuration',
        1107: 'Internal options file not found',
        1108: 'Value not found in internal_options.conf',
        1109: 'Option must be a digit',
        1110: 'Option value is out of the limits',
        1111: "Remote group file updates are only available in 'agent.conf' file",
        1112: "Empty files aren't supported",
        1113: "XML syntax error",
        1114: "Wazuh syntax error",

        # Rule: 1200 - 1299
        1200: 'Error reading rules from ossec.conf',
        1201: 'Error reading rule files',
        1202: 'Argument \'status\' must be: enabled, disabled or all',
        1203: 'Argument \'level\' must be a number or an interval separated by \'-\'',
        1204: 'Operation not implemented',
        1205: 'Requirement not valid. Valid ones are pci and gdpr',

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
        1405: 'Specified limit exceeds maximum allowed (1000)',
        1406: '0 is not a valid limit',
        1407: 'query does not match expected format',
        1408: 'Field does not exist.',
        1409: 'Invalid query operator.',
        1410: 'Selecting more than one field in distinct mode',
        1411: 'Timeframe is not valid',
        1412: 'Date filter not valid. Valid formats are timeframe or YYYY-MM-DD HH:mm:ss',

        # Decoders: 1500 - 1599
        1500: 'Error reading decoders from ossec.conf',
        1501: 'Error reading decoder files',

        # Syscheck/Rootcheck/AR: 1600 - 1699
        1600: 'There is no database for selected agent',  # Also, agent
        1601: 'Unable to restart syscheck/rootcheck',
        1602: 'Impossible to run syscheck/run due to agent is not active',
        1603: 'Invalid status. Valid statuses are: all, solved and outstanding',
        1650: 'Active response - Bad arguments',
        1651: 'Active response - Agent is not active',
        1652: 'Active response - Unable to run command',
        1653: 'Active response - Agent not available',
        1654: 'Unable to clear rootcheck database',

        # Agents:
        1700: 'Bad arguments. Accepted arguments: [id] or [name and ip]',
        1701: 'Agent does not exist',
        1702: 'Unable to restart agent(s)',
        1703: 'Action not available for Manager (Agent 000)',
        1704: 'Unable to load requested info from agent db',
        1705: 'There is an agent with the same name',
        1706: 'There is an agent with the same IP',
        1707: 'Impossible to restart agent due to it is not active',
        1708: 'There is an agent with the same ID',
        1709: 'Too short key size (<64)',
        1710: 'The group does not exist',
        1711: 'The group already exists',
        1712: 'Default group is not removable',
        1713: 'Error accessing repository',
        1714: 'Error downloading WPK file',
        1715: 'Error sending WPK file',
        1716: 'Error upgrading agent',
        1717: 'Cannot upgrade to a version higher than the manager',
        1718: 'Version not available',
        1719: 'Remote upgrade is not available for this agent version',
        1720: 'Agent disconnected',
        1721: 'Remote upgrade is not available for this agent OS version',
        1722: 'Incorrect format for group_id. Characters supported  a-z, A-Z, 0-9, ., _ and -. Max length is 255',
        1723: 'Hash algorithm not available',
        1724: 'Not a valid select field',
        1725: 'Error registering a new agent',
        1726: 'Ossec authd is not running',
        1727: 'Error listing group files',
        1728: 'Invalid node type',
        1729: 'Agent status not valid. Valid statuses are Active, Disconnected, Pending and Never Connected.',
        1730: 'Node does not exist',
        1731: 'Agent is not eligible for removal',
        1732: 'No agents selected',
        1733: 'Bad formatted version. Version must follow this pattern: vX.Y.Z .',
        1734: 'Error unsetting agent group',
        1735: 'Agent version is not compatible with this feature',
        1736: 'Error getting all groups',
        1737: 'Maximum number of groups per multigroup is 256',
        1738: 'Agent name is too long. Max length allowed for agent name is 128',
        1739: "Error getting agent's group sync",
        1740: 'Action only available for active agents',
        1741: 'Could not remove multigroup',
        1742: 'Error running XML syntax validator',
        1743: 'Error running Wazuh syntax validator',

        # Manager:

        # Database:
        2000: 'No such database file',
        2001: 'Incompatible version of SQLite',
        2002: 'Maximum attempts exceeded for sqlite3 execute',
        2003: 'Error in database request',
        2004: 'Database query not valid',
        2005: 'Could not connect to wdb socket',
        2006: 'Received JSON from Wazuh DB is not correctly formatted',
        2007: 'Error retrieving data from Wazuh DB',

        # Cluster
        3000: 'Cluster',
        3001: 'Error creating zip file',
        3002: 'Error creating PID file',
        3003: 'Error deleting PID file',
        3004: 'Error in cluster configuration',
        3005: 'Error reading cluster JSON file',
        3006: 'Error reading cluster configuration',
        3007: 'Client.keys file received in master node',
        3008: 'Received invalid agent status',
        3009: 'Error executing request to internal socket',
        3010: 'Received the status/group of an unexisting agent',
        3011: 'Agent info file received in a worker node',
        3012: 'Cluster is not running',
        3013: 'Cluster is disabled',
        3015: 'Cannot access directory',
        3016: 'Received an error response',
        3017: 'The agent is not reporting to any manager',
        3018: 'Error sending request',
        3019: 'Wazuh is running in cluster mode: {EXECUTABLE_NAME} is not available in worker nodes. Please, try again in the master node: {MASTER_IP}',

        # > 9000: Authd
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
                if isinstance(extra_message, dict):
                    self.message = self.ERRORS[code].format(**extra_message)
                else:
                    self.message = "{0}: {1}".format(self.ERRORS[code], extra_message)
            else:
                self.message = self.ERRORS[code]
        else:
            self.message = extra_message

    def __str__(self):
        return "Error {0} - {1}".format(self.code, self.message)
