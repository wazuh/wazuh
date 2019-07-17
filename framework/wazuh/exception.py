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
        1000: {'message': 'Wazuh Internal Error',
               'remediation': 'Please, check `WAZUH_HOME/logs/ossec.log` to get more information about the error'},
        1001: 'Error importing module',
        1002: 'Error executing command',
        1003: 'Command output not in json',
        1004: 'Malformed command output ',
        1005: {'message': 'Error reading file',
               'remediation': 'Please, ensure you have the right file permissions in Wazuh directories'},
        1006: {'message': 'File/directory does not exist',
               'remediation': 'Please, check if path to file/directory is correct'},
        1010: 'Unable to connect to queue',
        1011: 'Error communicating with queue',
        1012: {'message': 'Invalid message to queue'},
        1013: {'message': 'Unable to connect with socket',
               'remediation': 'Please, restart Wazuh to restore sockets'},
        1014: {'message': 'Error communicating with socket',
               'remediation': 'Please, restart Wazuh to restore sockets'},
        1015: 'Error agent version is null. Was the agent ever connected?',
        1016: {'message': 'Error moving file',
               'remediation': 'Please, ensure you have the required file permissions in Wazuh directories'},
        1017: 'Some Wazuh daemons are not ready yet in node \'{node_name}\' '
              '({not_ready_daemons})',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',
        1101: {'message': 'Requested component does not exist',
               'remediation': 'Run `WAZUH_PATH/bin/ossec-logtest -t` to check your configuration'},
        1102: {'message': 'Invalid section',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html) '
               'to get more information about configuration sections'},
        1103: {'message': 'Invalid field in section',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html) '
               'to get more information about configuration sections'},
        1104: {'message': 'Invalid type',
               'remediation': 'Insert a valid type'},
        1105: 'Error reading API configuration',
        1106: {'message': 'Requested section not present in configuration',
               'remediation': 'Please, check your configuration file. '
               'You can visit [official documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html) '
               'to get more information about configuration sections'},
        1107: 'Internal options file not found',
        1108: 'Value not found in internal_options.conf',
        1109: 'Option must be a digit',
        1110: 'Option value is out of the limits',
        1111: "Remote group file updates are only available in 'agent.conf' file",
        1112: {'message': 'Empty files are not supported',
               'remediation': 'Please, provide another file'
               },
        1113: {'message': 'XML syntax error',
               'remediation': 'Please, ensure file content has correct XML'
               },
        1114: "Wazuh syntax error",
        1115: {'message': 'Error executing verify-agent-conf',
               'remediation': 'Please, check your configuration file and try again'
               },
        1116: {'message': "Requested component configuration does not exist",
               'remediation': "Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html#get-active-configuration) to check available component configurations"
               },
        1117: {'message': "Unable to connect with component. The component might be disabled."},
        1118: {'message': "Could not request component configuration"},
        1119: "Directory '/tmp' needs read, write & execution permission for 'ossec' user",
        1120: {'message': "Error adding agent. HTTP header 'X-Forwarded-For' not present in a behind_proxy_server API configuration",
               'remediation': "Please, make sure your proxy is setting 'X-Forwarded-For' HTTP header"
               },
        1121: {'message': "Error connecting with socket"},
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
        1205: {'message': 'Requirement not valid',
               'remediation': 'Please indicate one of the following values:'
               },
        1206: {'message': 'Duplicated rule ID',
               'remediation': 'Please check your configuration, two or more rules have the same ID, visit [official documentation]https://documentation.wazuh.com/3.x/user-manual/ruleset/custom.html '
                              ' to get more information about how to configure the rules'
               },
        1207: {'message': 'Error reading rule files, wrong permissions',
               'remediation': 'Please, check your permissions over the file'
               },

        # Stats: 1300 - 1399
        1307: {'message': 'Invalid parameters',
               'remediation': 'Please, check that the update is correct, there is a problem while reading the results, contact us at [official repository](https://github.com/wazuh/wazuh/issues)'
               },
        1308: {'message': 'Stats file has not been created yet',
              'remediation': 'Stats files are generated at 12 PM. '
              'Please, try again later'},
        1309: 'Statistics file damaged',
        1310: {'message': 'Stats file does not exist',
              'remediation': 'Please, try to use another date'},

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: 'Invalid order. Order must be \'asc\' or \'desc\'',
        1403: {'message': 'Not a valid sort field ',
               'remediation': 'Please, use only allowed sort fields'
               },
        1404: 'A field must be specified to order the data',
        1405: {'message': 'Specified limit exceeds maximum allowed',
               'remediation': 'Please select a limit between 1 and 1000'
               },
        1406: {'message': '0 is not a valid limit',
               'remediation': 'Please select a limit between 1 and 1000'
               },
        1407: 'query does not match expected format',
        1408: 'Field does not exist.',
        1409: 'Invalid query operator.',
        1410: 'Selecting more than one field in distinct mode',
        1411: 'Timeframe is not valid',
        1412: 'Date filter not valid. Valid formats are timeframe or YYYY-MM-DD HH:mm:ss',
        1413: {'message': 'Error reading rules file'},
        1414: {'message': 'Error reading rules file',
               'remediation': 'Please, make sure you have read permissions over the file'
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
        1600: {'message': 'There is no database for selected agent with id',
               'remediation': 'Please, upgrade wazuh to v3.7.0 or newer. Visit '
                              'https://documentation.wazuh.com/current/installation-guide/upgrading/index.html'
                              ' to obtain more information on upgrading wazuh'
               },
        1601: {'message': 'Impossible to run FIM scan, agent is not active',
               'remediation': 'Please, ensure selected agent is active and connected to the manager. Visit '
                              'https://documentation.wazuh.com/current/user-manual/registering/index.html and '
                              'https://documentation.wazuh.com/current/user-manual/agents/agent-connection.html'
                              'to obtain more information on registering and connecting agents'
               },
        1603: 'Invalid status. Valid statuses are: all, solved and outstanding',
        1605: 'Impossible to run policy monitoring scan due to agent is not active',
        1650: 'Active response - Command not specified',
        1651: 'Active response - Agent is not active',
        1652: 'Active response - Unable to run command',
        1653: 'Active response - Agent ID not specified',
        1654: 'Unable to clear rootcheck database',
        1655: 'Active response - Command not available',

        # Agents: 1700 - 1799
        1700: 'Bad arguments. Accepted arguments: [id] or [name and ip]',
        1701: {'message': 'Agent does not exist',
               'remediation': 'Please, use `GET /agents?select=id,name` to find all available agents'
               },
        1702: {'message': 'Unable to restart agent(s)',
               'remediation': 'Please make sure the agent exists. it is active and it is not the manager(Agent 000)'
               },
        1703: {'message': 'Action not available for Manager (Agent 000)',
               'remediation': 'Please, use `GET /agents?select=id,name` to find all available agents and make sure you select an agent other than 000'
               },
        1704: 'Unable to load requested info from agent db',
        1705: {'message': 'There is an agent with the same name',
               'remediation': 'Please choose another name'
               },
        1706: {'message': 'There is an agent with the same IP or the IP is invalid',
               'remediation': 'Please choose another IP'
               },
        1707: {'message': 'Impossible to restart non-active agent',
               'remediation': 'Please, make sure agent is active before attempting to restart'
               },
        1708: {'message': 'There is an agent with the same ID',
               'remediation': 'Please choose another ID'
               },
        1709: {'message': 'Too short key size',
               'remediation': 'The necessary size for the key is (<64)'
               },
        1710: {'message': 'The group does not exist',
               'remediation': 'Please, `GET /agents/groups` to find all available groups'
               },
        1711: {'message': 'The group already exists',
               'remediation': 'Please, use another group ID'
               },
        1712: {'message': 'Default group is not deletable',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/3.x/user-manual/agents/grouping-agents.html)'
                              'to get more information'
               },
        1713: {'message': 'Error accessing repository',
               'remediation': 'Please check your internet connection and try again'
               },
        1714: {'message': 'Error downloading WPK file',
               'remediation': 'Please check your internet connection and try again'
               },
        1715: {'message': 'Error sending WPK file',
               'remediation': 'Please check your internet connection, ensure the agent is active and try again'
               },
        1716: {'message': 'Error upgrading agent',
               'remediation': 'Please check that it is a new version and try again'
               },
        1717: {'message': 'Cannot upgrade to a version higher than the manager',
               'remediation': 'The agent cannot have a more recent version than the manager, please update the manager first'
               },
        1718: {'message': 'Version not available',
               'remediation': 'Please check the version again or check our repository at [official repository](https://github.com/wazuh/wazuh)'
               },
        1719: {'message': 'Remote upgrade is not available for this agent version',
               'remediation': 'Please, follow this for agent upgrading: [official documentation](https://documentation.wazuh.com/3.x/user-manual/agents/remote-upgrading/upgrading-agent.html)'
               },
        1720: {'message': 'Agent disconnected',
               'remediation': 'Please make sure the agent is active'
               },
        1721: {'message': 'Remote upgrade is not available for this agent OS version',
               'remediation': 'Sorry, the remote update is not available for this OS'
               },
        1722: {'message': 'Incorrect format for group_id',
               'remediation': 'Characters supported  a-z, A-Z, 0-9, ., _ and -. Max length is 255'
               },
        1723: 'Hash algorithm not available',
        1724: {'message': 'Not a valid select field ',
               'remediation': 'Please, use only allowed select fields'
               },
        1725: {'message': 'Error registering a new agent',
               'remediation': 'Please check all data fields and try again'
               },
        1726: {'message': 'Ossec authd is not running',
               'remediation': 'Please, visit our documentation to get more information: [official documentation](https://documentation.wazuh.com/current/user-manual/agents/registering-agents/register-agent-authd.html)'
               },
        1727: {'message': 'Error listing group files',
               'remediation': 'Please, use `GET /agents/groups/:group_id/files` to get all available group files'
               },
        1728: {'message': 'Invalid node type',
               'remediation': 'Valid types are `master` and `worker`. Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-cluster.html) '
                          'to get more information about cluster configuration'},
        1729: {'message': 'Agent status not valid. Valid statuses are Active, Disconnected, Pending and NeverConnected',
               'remediation': 'Please check used status and try again.'
               },
        1730: {'message': 'Node does not exist',
               'remediation': 'Make sure the name is correct and that the node is up. You can check it using '
                          '[`cluster_control -l`](https://documentation.wazuh.com/current/user-manual/reference/tools/cluster_control.html#get-connected-nodes)'},
        1731: {'message': 'Agent is not eligible for removal',
               'remediation': "Please check the agent's status [official documentation](https://documentation.wazuh.com/3.x/user-manual/agents/restful-api/remove.html)"
               },
        1732: {'message': 'No agents selected',
               'remediation': 'Please select an agent or the operation cannot be performed'
               },
        1733: 'Bad formatted version. Version must follow this pattern: vX.Y.Z .',
        1734: {'message': 'Error removing agent from group',
               'remediation': 'Agent does not belong to specified group, to assign the agent to a group follow: [official documentation](https://documentation.wazuh.com/3.x/user-manual/agents/grouping-agents.html)'
               },
        1735: {'message': 'Agent version is not compatible with this feature',
               'remediation': 'Please update the agent, in case the problem persists contact us at: [official repository](https://github.com/wazuh/wazuh/issues)'
               },
        1736: {'message': 'Error getting all groups',
               'remediation': 'Please, use `GET /agents/groups` to find all available groups'
               },
        1737: {'message': 'Maximum number of groups per multigroup is 256',
               'remediation': 'Please choose another group or remove an agent from the target group'
               },
        1738: {'message': 'Agent name is too long',
               'remediation': 'Max length allowed for agent name is 128'
               },
        1739: {'message': 'Error getting agents group sync',
               'remediation': 'Please check that the agent and the group are correctly created [official documentation](https://documentation.wazuh.com/3.x/user-manual/agents/command-line/register.html)'
               },
        1740: {'message': 'Action only available for active agents',
               'remediation': 'Please activate the agent to be able to synchronize'
               },
        1741: 'Could not remove multigroup',
        1742: 'Error running XML syntax validator',
        1743: 'Error running Wazuh syntax validator',
        1744: 'Invalid chunk size',
        1745: "Agent only belongs to 'default' and it cannot be unassigned from this group.",
        1746: {'message': "Could not parse current client.keys file"},
        1747: {'message': "Could not remove agent group assigment from database"},
        1748: {'message': "Could not remove agent files"},
        1749: {'message': "Downgrading an agent requires the force flag.",
               'remediation': "Use -F to force the downgrade"
               },
        1750: {'message': 'No parameters provided for request',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html) to get more information about available requests'
               },

        # CDB List: 1800 - 1899
        1800: {'message': 'Bad format in CDB list {path}'},
        1801: {'message': 'Wrong \'path\' parameter',
               'remediation': 'Please, provide a correct path'},
        1802: {'message': 'Lists file not found',
               'remediation': 'Please, use `GET /lists/files` to find all available lists'},
        1803: {'message': 'Error reading lists file',
               'remediation': 'Please, make sure you have read permissions over the file'
               },
        1804: {'message': 'Error reading lists file',
               'remediation': 'Please, make sure you provide a correct filepath'
               },

        # Manager:
        1900: 'Error restarting manager',
        1901: {'message': '\'execq\' socket has not been created'
               },
        1902: {'message': 'Connection to \'execq\' socket failed'
               },
        1903: 'Error deleting temporary file from API',
        1904: {'message': 'Bad data from \'execq\''
               },
        1905: {'message': 'File could not be updated, it already exists',
               'remediation': 'Please, provide a different file or set overwrite=True to overwrite actual file'
               },
        1906: {'message': 'File does not exist',
               'remediation': 'Please, provide a different file or make sure provided file path is correct'
               },
        1907: {'message': 'File could not be deleted',
               'remediation': 'Please, ensure you have the right file permissions'
               },
        1908: {'message': 'Error validating configuration',
               'remediation': 'Please, fix the corrupted files'
              },
        1909: {'message': 'Content of file is empty',
               'remediation': 'Try to upload another non-empty file'},
        1910: {'message': 'Content-type header is mandatory',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html#update-local-file-at-any-cluster-node)'
                              ' to get more information about how to configure a cluster'},
        1911: {'message': 'Error parsing body request to UTF-8',
               'remediation': 'Please, check if the file content to be uploaded is right'},
        1912: {'message': 'Body is empty',
               'remediation': 'Please, check the content of the file to be uploaded'},

        # Database:
        2000: {'message': 'No such database file'},
        2001: {'message': 'Incompatible version of SQLite'},
        2002: {'message': 'Maximum attempts exceeded for sqlite3 execute'},
        2003: {'message': 'Error in wazuhdb request',
               'remediation': 'Make sure the your request is correct'},
        2004: {'message': 'Database query not valid'},
        2005: {'message': 'Could not connect to wdb socket'},
        2006: {'message': 'Received JSON from Wazuh DB is not correctly formatted'},
        2007: {'message': 'Error retrieving data from Wazuh DB'},

        # Cluster
        3000: 'Cluster',
        3001: 'Error creating zip file',
        3002: {'message': 'Error creating PID file'},
        3003: {'message': 'Error deleting PID file'},
        3004: {'message': 'Error in cluster configuration',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-cluster.html)'
                              ' to get more information about how to configure a cluster'},
        3005: 'Error reading cluster JSON file',
        3006: {'message': 'Error reading cluster configuration',
               'remediation': 'Please, visit [official documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-cluster.html)'
                              ' to get more information about how to configure a cluster'},
        3007: 'Client.keys file received in master node',
        3008: 'Received invalid agent status',
        3009: {'message': 'Error executing distributed API request',
               'remediation': ''},
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
        3020: {'message': 'Timeout sending request',
               'remediation': 'Please, try to make the request again'},
        3021: 'Timeout executing API request',
        3022: {'message': 'Unknown node ID',
               'remediation': 'Check the name of the node'},
        3023: {'message': 'Worker node is not connected to master',
               'remediation': 'Check the cluster.log located at WAZUH_HOME/logs/cluster.log file to see if there are '
                              'connection errors. Restart the `wazuh-manager` service.'},
        3024: "Length of command exceeds limit defined in wazuh.cluster.common.Handler.cmd_len.",
        3025: {'message': "Could not decrypt message",
               'remediation': "Check the cluster key is correct in the worker's "
                              "[ossec.conf](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#key)"
                              ", ensure it is the same that the master's."},
        3026: "Error sending request: Memory error. Request chunk size divided by 2.",
        3027: "Unknown received task name",
        3028: {'message': "Worker node ID already exists",
               'remediation': "Check and fix [worker names](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service."},
        3029: {"message": "Connected worker with same name as the master",
               "remediation": "Check and fix the [worker name](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service in the node"},
        3030: {'message': 'Worker does not belong to the same cluster',
               'remediation': "Change the [cluster name](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html#name)"
                              " in the worker configuration to match the master's and restart the `wazuh-manager` service"},
        3031: {'message': "Worker and master versions are not the same",
               'remediation': "[Update](https://documentation.wazuh.com/current/installation-guide/upgrading/index.html)"
                              " master and workers to the same version."},
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

        error_details = self.ERRORS[self._code] if not cmd_error else extra_message
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

        self._remediation = code_remediation if extra_remediation is None else f"{code_remediation}: {extra_remediation}"

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
