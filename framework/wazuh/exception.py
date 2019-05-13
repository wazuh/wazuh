# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from copy import deepcopy


GENERIC_ERROR_MSG = "Wazuh Internal Error. See log for more detail"


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
        1017: 'Wazuh is restarting',
        1018: 'Wazuh is stopped. Start Wazuh before using the API.',
        1019: 'There is a failed process. Review that before using the API.',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',
        1101: 'Requested component does not exist',
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
        1115: "Error executing verify-agent-conf",
        1116: "Requested component configuration does not exist",
        1117: "Unable to connect with component. The component might be disabled.",
        1118: "Could not request component configuration",

        # Rule: 1200 - 1299
        1200: {'message': 'Error reading rules from `WAZUH_HOME/etc/ossec.conf`',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1201: {'message': 'Error reading rule files',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1202: {'message': 'Argument \'status\' must be: enabled, disabled or all',
               'remediation': 'Please indicate one of the following states: enabled, disabled, all'
               },
        1203: {'message': 'Error in argument \'level\'',
               'remediation': 'Argument \'level\' must be a number or an interval separated by \'-\''
               },
        1204: {'message': 'Operation not implemented',
               'remediation': 'Please contact us: [official repository]https://github.com/wazuh/wazuh/issues'
               },
        1205: {'message': 'Requirement not valid. Valid ones are pci and gdpr',
               'remediation': 'Please indicate one of the following values: pci or gdpr'
               },
        1206: {'message': 'Duplicated rule ID',
               'remediation': 'Please check your configuration, two or more rules have the same ID, visit [official documentation]https://documentation.wazuh.com/3.x/user-manual/ruleset/custom.html'
               },
        1207: {'message': 'Error reading rule files, wrong permissions',
               'remediation': 'Please, check your permissions over the file'
               },

        # Stats: 1300 - 1399
        1307: 'Invalid parameters',
        1308: 'Stats file has not been created yet',
        1309: 'Statistics file damaged',

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: 'Invalid order. Order must be \'asc\' or \'desc\'',
        1403: {'message': 'Not a valid sort field ',
               'remediation': 'Please, use only allowed sort fields'
               },
        1404: 'A field must be specified to order the data',
        1405: 'Specified limit exceeds maximum allowed (1000)',
        1406: '0 is not a valid limit',
        1407: 'query does not match expected format',
        1408: 'Field does not exist.',
        1409: 'Invalid query operator.',
        1410: 'Selecting more than one field in distinct mode',
        1411: 'Timeframe is not valid',
        1412: 'Date filter not valid. Valid formats are timeframe or YYYY-MM-DD HH:mm:ss',
        1413: {'message': 'Error reading rules file'},
        1414: {'message': 'Error reading rules file',
               'remediation': 'Please, make sure you have read permissions on the file'
               },
        1415: {'message': 'Rules file not found',
               'remediation': 'Please, use GET /rules/files to list all available rules'
               },

        # Decoders: 1500 - 1599
        1500: {'message': 'Error reading decoders from ossec.conf',
               'remediation': 'Please, visit https://documentation.wazuh.com/current/user-manual/ruleset/custom.html'
                              'to get more information on adding or modifying existing decoders'
               },
        1501: {'message': 'Error reading decoders file'
               },
        1502: {'message': 'Error reading decoders file',
               'remediation': 'Please, make sure you have read permissions on the file'
               },
        1503: {'message': 'Decoders file not found',
               'remediation': 'Please, use GET /decoders/files to list all available decoders'
               },

        # Syscheck/Rootcheck/AR: 1600 - 1699
        1600: 'There is no database for selected agent',  # Also, agent
        1601: 'Unable to restart syscheck/rootcheck',
        1603: 'Invalid status. Valid statuses are: all, solved and outstanding',
        1604: 'Impossible to run FIM scan due to agent is not active',
        1605: 'Impossible to run policy monitoring scan due to agent is not active',
        1650: 'Active response - Command not specified',
        1651: 'Active response - Agent is not active',
        1652: 'Active response - Unable to run command',
        1653: 'Active response - Agent ID not specified',
        1654: 'Unable to clear rootcheck database',
        1655: 'Active response - Command not available',

        # Agents: 1700 - 1799
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
        1724: {'message': 'Not a valid select field',
               'remediation': 'Use a valid field'},
        1725: 'Error registering a new agent',
        1726: 'Ossec authd is not running',
        1727: 'Error listing group files',
        1728: {'message': 'Invalid node type',
               'remediation': 'Valid types are "master" and "worker"'},
        1729: 'Agent status not valid. Valid statuses are Active, Disconnected, Pending and Never Connected.',
        1730: {'message': 'Node does not exist',
               'remediation': 'Make sure the name is correct and that the node is up. You can check it using '
                              '[`cluster_control -l`](https://documentation.wazuh.com/current/user-manual/reference/tools/cluster_control.html#get-connected-nodes)'},
        1731: 'Agent is not eligible for removal',
        1732: 'No agents selected',
        1733: 'Bad formatted version. Version must follow this pattern: vX.Y.Z .',
        1734: 'Agent does not belong to the specified group',
        1735: 'Agent version is not compatible with this feature',
        1736: 'Error getting all groups',
        1737: 'Maximum number of groups per multigroup is 256',
        1738: 'Agent name is too long. Max length allowed for agent name is 128',
        1739: "Error getting agent's group sync",
        1740: 'Action only available for active agents',
        1741: 'Could not remove multigroup',
        1742: 'Error running XML syntax validator',
        1743: 'Error running Wazuh syntax validator',
        1744: 'Invalid chunk size',
        1745: "Agent only belongs to 'default' and it cannot be unset from this group.",
        1746: "Could not parse current client.keys file",
        1747: "Could not remove agent group assigment from database",
        1748: "Could not remove agent files",

        # CDB List: 1800 - 1899
        1800: 'Bad format in CDB list {path}',
        1801: '\'path\' parameter is wrong',

        # Manager:
        1900: 'Error restarting manager',
        1901: '\'execq\' socket has not been created',
        1902: 'Could not connect to \'execq\' socket',
        1903: 'Error deleting temporary file from API',
        1904: 'Bad data from \'execq\'',
        1905: 'File was not updated because it already exists',
        1906: 'File does not exist',
        1907: 'File could not be deleted',

        # Database:
        2000: 'No such database file',
        2001: 'Incompatible version of SQLite',
        2002: 'Maximum attempts exceeded for sqlite3 execute',
        2003: 'Error in wazuhdb request',
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
        3009: 'Error executing distributed API request',
        3010: 'Received the status/group of an unexisting agent',
        3011: 'Agent info file received in a worker node',
        3012: 'Cluster is not running',
        3013: {'message': 'Cluster is disabled in `WAZUH_HOME/etc/ossec.conf`',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-cluster.html)'
                              ' to get more information about how to configure a cluster'
               },
        3015: 'Cannot access directory',
        3016: 'Received an error response',
        3017: 'The agent is not reporting to any manager',
        3018: 'Error sending request',
        3019: 'Wazuh is running in cluster mode: {EXECUTABLE_NAME} is not available in worker nodes. Please, try again in the master node: {MASTER_IP}',
        3020: 'Timeout sending request',
        3021: 'Timeout executing API request',
        3022: 'Unknown node ID',
        3023: {'message': 'Worker node is not connected to master',
               'remediation': 'Check the cluster.log located at WAZUH_HOME/logs/cluster.log file to see if there are '
                              'connection errors. Restart the `wazuh-manager` service.'},
        3024: "Length of command exceeds limit defined in wazuh.cluster.common.Handler.cmd_len.",
        3025: {'message': "Could not decrypt message",
               'remediation': "Check the cluster key is correct in the worker's "
                              "[ossec.conf](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#key)"
                              " is the same that the master's."},
        3026: "Error sending request: Memory error. Request chunk size divided by 2.",
        3027: "Unknown received task name",
        3028: {'message': "Worker node ID already exists",
               'remediation': "Change one of the two [worker names](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service."},
        3029: {"message": "Connected worker with same name as the master",
               "remediation": "Change the [worker name](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service in the node"},
        3030: {'message': 'Worker does not belong to the same cluster',
               'remediation': "Change the [cluster name](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#name)"
                              " in the worker configuration to match the master's and restart the `wazuh-manager` service"},
        3031: {'message': "Worker and master versions are not the same",
               'remediation': "[Update](https://documentation.wazuh.com/current/installation-guide/upgrading/index.html)"
                              " both master and worker to the same version."},
        3032: "Could not forward DAPI request. Connection not available.",
        3033: "Payload length exceeds limit defined in wazuh.cluster.common.Handler.request_chunk.",
        3034: "Error sending file. File not found."

        # > 9000: Authd
    }

    def __init__(self, code, extra_message=None, extra_remediation=None, cmd_error=False, dapi_errors=None):
        """
        Creates a Wazuh Exception.

        :param code: Exception code.
        :param extra_message: Adds an extra message to the error description.
        :param extra_remediation: Adds an extra description to remediation
        :param cmd_error: If it is a custom error code (i.e. ossec commands), the error description will be the message.
        :param dapi_errors: dict with details about node and logfile. I.e.:
                            {'master-node': {'error': 'Wazuh Internal error',
                                             'logfile': WAZUH_HOME/logs/api.log}
                            }
        """
        self._code = code
        self._extra_message = extra_message
        self._extra_remediation = extra_remediation
        self._cmd_error = cmd_error
        self._dapi_errors = {} if dapi_errors is None else deepcopy(dapi_errors)

        error_details = self.ERRORS[self._code]
        if isinstance(error_details, dict):
            code_message, code_remediation = error_details.get('message', ''), error_details.get('remediation', None)
        else:
            code_message, code_remediation = error_details, None

        if not cmd_error:
            if extra_message:
                if isinstance(extra_message, dict):
                    self._message = code_message.format(**extra_message)
                else:
                    self._message = "{0}: {1}".format(code_message, extra_message)
            else:
                self._message = code_message
        else:
            self._message = extra_message

        self._remediation = code_remediation if extra_remediation is None else f"{code_remediation}. {extra_remediation}"

    def __str__(self):
        return "Error {0} - {1}".format(self._code, self._message)

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        if not isinstance(other, WazuhException):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __or__(self, other):
        result = self.__class__(**self.to_dict())
        if isinstance(other, WazuhException):
            result.dapi_errors = {**self._dapi_errors, **other.dapi_errors}
        return result

    def to_dict(self):
        return {'code': self._code,
                'extra_message': self._extra_message,
                'extra_remediation': self._extra_remediation,
                'cmd_error': self._cmd_error,
                'dapi_errors': self._dapi_errors
                }

    @property
    def message(self):
        return self._message

    @property
    def remediation(self):
        return self._remediation

    @property
    def dapi_errors(self):
        return self._dapi_errors

    @dapi_errors.setter
    def dapi_errors(self, value):
        self._dapi_errors = value

    @property
    def code(self):
        return self._code

    @classmethod
    def from_dict(cls, dct):
        return cls(**dct)


class WazuhInternalError(WazuhException):
    """
    This type of exception is raised when an unexpected error in framework code occurs,
    which means an internal error could not be handled
    """
    pass


class WazuhError(WazuhException):
    """
    This type of exception is raised as a controlled response to a bad request from user
    that cannot be performed properly
    """
    pass


class WazuhClusterError(WazuhException):
    """
    This type of exception is raised inside the cluster.
    """
    pass
