# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from copy import deepcopy
from wazuh.core.common import MAX_SOCKET_BUFFER_SIZE, wazuh_version as wazuh_full_version


GENERIC_ERROR_MSG = "Wazuh Internal Error. See log for more detail"
WAZUH_VERSION = 'current' if wazuh_full_version == '' else '.'.join(wazuh_full_version.split('.')[:2]).lstrip('v')


class WazuhException(Exception):
    """
    Wazuh Exception object.
    """

    ERRORS = {
        # < 999: API

        # Wazuh: 0999 - 1099
        999: 'Incompatible version of Python',
        1000: {'message': 'Wazuh Internal Error',
               'remediation': 'Please, check `WAZUH_HOME/logs/ossec.log`, `WAZUH_HOME/logs/cluster.log` and '
                              '`WAZUH_HOME/logs/api.log` to get more information about the error'},
        1001: 'Error importing module',
        1002: 'Error executing command',
        1003: 'Command output not in JSON',
        1004: 'Malformed command output ',
        1005: {'message': 'Error reading file',
               'remediation': 'Please, ensure you have the right file permissions in Wazuh directories'},
        1006: {'message': 'File/directory does not exist or there is a problem with the permissions',
               'remediation': 'Please, check if path to file/directory is correct and `ossec` '
                              'has the appropriate permissions'},
        1010: 'Unable to connect to queue',
        1011: 'Error communicating with queue',
        1012: {'message': 'Invalid message to queue'},
        1013: {'message': 'Unable to connect with socket',
               'remediation': 'Please, restart Wazuh to restore sockets'},
        1014: {'message': 'Error communicating with socket',
               'remediation': 'Please, restart Wazuh to restore sockets'},
        1015: 'Agent version is null. Was the agent ever connected?',
        1016: {'message': 'Error moving file',
               'remediation': 'Please, ensure you have the required file permissions in Wazuh directories'},
        1017: 'Some Wazuh daemons are not ready yet in node "{node_name}" ({not_ready_daemons})',
        1018: 'Body request is not a valid JSON',
        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',
        1101: {'message': 'Requested component does not exist',
               'remediation': 'Run `WAZUH_PATH/bin/ossec-logtest -t` to check your configuration'},
        1102: {'message': 'Invalid section',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html) '
                              'to get more information about configuration sections'},
        1103: {'message': 'Invalid field in section',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html) '
                              'to get more information about configuration sections'},
        1104: {'message': 'Invalid type',
               'remediation': 'Insert a valid type'},
        1105: 'Error reading API configuration',
        1106: {'message': 'Requested section not present in configuration',
               'remediation': 'Please, check your configuration file. '
                              f'You can visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html) '
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
               'remediation': f"Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/reference.html#operation/api.controllers.agents_controller.get_agent_config) to check available component configurations"
               },
        1117: {'message': "Unable to connect with component. The component might be disabled."},
        1118: {'message': "Could not request component configuration"},
        1119: "Directory '/tmp' needs read, write & execution permission for 'ossec' user",
        1120: {
            'message': "Error adding agent. HTTP header 'X-Forwarded-For' not present in a behind_proxy_server API configuration",
            'remediation': "Please, make sure your proxy is setting 'X-Forwarded-For' HTTP header"
            },
        1121: {'message': "Error connecting with socket"},
        1122: {'message': 'Experimental features are disabled',
               'remediation': 'Experimental features can be enabled in WAZUH_PATH/configuration/api.yaml or '
                              'using API endpoint https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.manager_controller.put_api_config or '
                              'https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.cluster_controller.put_api_config'},
        1123: {'message': f"Error communicating with socket. Query too long, maximum allowed size for queries is {MAX_SOCKET_BUFFER_SIZE // 1024} KB"},
        1124: {'message': 'Remote command detected',
               'remediation': 'To solve this issue please enable the remote commands in the API settings or add an exception: LINK_TODO'},

        # Rule: 1200 - 1299
        1200: {'message': 'Error reading rules from `WAZUH_HOME/etc/ossec.conf`',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1201: {'message': 'Error reading rule files',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html)'
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
               'remediation': f'Please check your configuration, two or more rules have the same ID, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/ruleset/custom.html)'
                              ' to get more information about how to configure the rules'
               },
        1207: {'message': 'Error reading rule files, wrong permissions',
               'remediation': 'Please, check your permissions over the file'
               },
        1208: {'message': 'The rule does not exist or you do not have permission to see it',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },

        # Stats: 1300 - 1399
        1301: {'message': 'Invalid date',
               'remediation': 'Please, make sure you use a valid date value)'
               },
        1307: {'message': 'Invalid parameters',
               'remediation': 'Please, check that the update is correct, there is a problem while reading the results, contact us at [official repository](https://github.com/wazuh/wazuh/issues)'
               },
        1308: {'message': 'Stats file does not exist',
               'remediation': 'Stats files are usually generated at 12 PM on a daily basis'},
        1309: 'Statistics file damaged',

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: {'message': 'Invalid sort_ascending field',
               'remediation': 'Please, use only true if ascending or false if descending'
               },
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
        1407: 'Query does not match expected format',
        1408: 'Field does not exist.',
        1409: 'Invalid query operator.',
        1410: 'Selecting more than one field in distinct mode',
        1411: 'TimeFrame is not valid',
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
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/ruleset/custom.html)'
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
        1504: {'message': 'The decoder does not exist or you do not have permission to see it',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about the decoders'
               },

        # Syscheck/AR: 1600 - 1699
        1600: {'message': 'There is no database for selected agent with id',
               'remediation': 'Please, upgrade wazuh to v3.7.0 or newer. Visit '
                              f'https://documentation.wazuh.com/{WAZUH_VERSION}/upgrade-guide/index.html'
                              ' to obtain more information on upgrading wazuh'
               },
        1601: {'message': 'Impossible to run FIM scan, agent is not active',
               'remediation': 'Please, ensure selected agent is active and connected to the manager. Visit '
                              f'https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/registering/index.html and '
                              f'https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/agents/agent-connection.html'
                              'to obtain more information on registering and connecting agents'
               },
        1603: 'Invalid status. Valid statuses are: all, solved and outstanding',
        1605: 'Impossible to run policy monitoring scan due to agent is not active',
        1650: 'Active response - Command not specified',
        1651: 'Active response - Agent is not active',
        1652: 'Active response - Unable to run command',
        1653: 'Active response - Agent ID not specified',
        1655: 'Active response - Command not available',
        1656: {'message': 'No parameters provided for request',
               'remediation': 'Please, visit the official documentation '
                              f'(https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/reference.html#tag/active-response) '
                              'to get more information about `active-response` API call'},

        # Agents: 1700 - 1799
        1700: 'Bad arguments. Accepted arguments: [id] or [name and ip]',
        1701: {'message': 'Agent does not exist',
               'remediation': 'Please, use `GET /agents?select=id,name` to find all available agents'
               },
        1702: {'message': 'Unable to restart agent(s)',
               'remediation': 'Please make sure the agent exists, it is active and it is not the manager (agent 000)'
               },
        1703: {'message': 'Action not available for Manager (agent 000)',
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
               'remediation': 'The necessary size for the key is 64 characters at least'
               },
        1710: {'message': 'The group does not exist',
               'remediation': 'Please, use `GET /agents/groups` to find all available groups'
               },
        1711: {'message': 'The group already exists',
               'remediation': 'Please, use another group ID'
               },
        1712: {'message': 'Default group is not deletable',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/agents/grouping-agents.html)'
                              'to get more information'
               },
        1713: {'message': 'Error accessing repository',
               'remediation': 'Please check your internet connection and try again'
               },
        1714: {'message': 'Error downloading WPK file',
               'remediation': 'Please check your internet connection and try again'
               },
        1722: {'message': 'Incorrect format for group_id',
               'remediation': 'Characters supported  a-z, A-Z, 0-9, ., _ and -. Max length is 255'
               },
        1723: 'Hash algorithm not available',
        1724: {'message': 'Not a valid select field',
               'remediation': 'Please, use only allowed select fields'
               },
        1725: {'message': 'Error registering a new agent',
               'remediation': 'Please check all data fields and try again'
               },
        1726: {'message': 'Ossec authd is not running',
               'remediation': f'Please, visit our documentation to get more information: https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/registering/index.html#registering-the-wazuh-agent-using-simple-registration-service'
               },
        1727: {'message': 'Error listing group files',
               'remediation': 'Please, use `GET /agents/groups/:group_id/files` to get all available group files'
               },
        1728: {'message': 'Invalid node type',
               'remediation': f'Valid types are `master` and `worker`. Please, visit https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/configuring-cluster/index.html '
                              'to get more information about cluster configuration'},
        1729: {
            'message': 'Agent status not valid. Valid statuses are active, disconnected, pending and never_connected',
            'remediation': 'Please check used status and try again.'
            },
        1730: {'message': 'Node does not exist',
               'remediation': 'Make sure the name is correct and that the node is up. You can check it using '
                              f'`cluster_control -l` (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/tools/cluster_control.html#get-connected-nodes)'},
        1731: {'message': 'Agent is not eligible for removal',
               'remediation': f"Please check the agent's status official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/agents/agent-life-cycle.html#registered-agent)"
               },
        1732: {'message': 'No agents selected',
               'remediation': 'Please select an agent to perform the operation.'
               },
        1733: 'Bad formatted version. Version must follow this pattern: vX.Y.Z .',
        1734: {'message': 'Error removing agent from group',
               'remediation': f'Agent does not belong to specified group, to assign the agent to a group follow: https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/agents/grouping-agents.html'
               },
        1735: {'message': 'Agent version is not compatible with this feature',
               'remediation': 'Please update the agent, in case the problem persists contact us at: https://github.com/wazuh/wazuh/issues'
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
               'remediation': f'Please check that the agent and the group are correctly created. Official documentation: https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/agents/grouping-agents.html'
               },
        1740: {'message': 'Action only available for active agents',
               'remediation': 'Please activate the agent to synchronize it'
               },
        1741: 'Could not remove multigroup',
        1742: 'Error running XML syntax validator',
        1743: 'Error running Wazuh syntax validator',
        1744: 'Invalid chunk size',
        1745: "Agent only belongs to 'default' and it cannot be unassigned from this group.",
        1746: {'message': "Could not parse current client.keys file"},
        1747: {'message': "Could not remove agent group assigment from database"},
        1748: {'message': "Could not remove agent files"},
        1749: {'message': "Downgrading an agent requires the [force] flag.",
               'remediation': "Use force=1 parameter to force the downgrade"
               },
        1750: {'message': 'Could not send restart command, active-response is disabled in the agent',
               'remediation': "You can activate it in agents' `WAZUH_HOME/etc/ossec.conf`"},
        1751: {'message': 'Could not assign agent to group',
               'remediation': 'Agent already belongs to specified group, please select another agent'},
        1752: {'message': 'Could not force single group for the agent'},
        1753: {'message': 'Could not assign group. Agent status is never_connected',
               'remediation': 'Please select another agent or connect your agent before assigning groups'},
        1754: {'message': 'Agent does not exist or you do not have permissions to access it',
               'remediation': 'Try listing all agents with GET /agents endpoint'},
        1755: {'message': 'The group does not have any agent assigned',
               'remediation': 'Please select another group or assign any agent to it'},
        1756: {'message': 'Upgrade procedure could not start. Agent already upgrading',
               'remediation': 'You can check the status of this task with the /agents/:agent_id/upgrade_result endpoint'
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

        1810: {'message': 'Upgrade module\'s reserved exception IDs (1810-1899). '
                          'The error message will be the output of upgrade module'},

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
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/reference.html#operation/api.controllers.cluster_controller.put_files_node)'
                              ' to get more information about how to configure a cluster'},
        1911: {'message': 'Error parsing body request to UTF-8',
               'remediation': 'Please, check if the file content is valid UTF-8'},
        1912: {'message': 'Body is empty',
               'remediation': 'Please, check the content of the file to be uploaded'},

        # Database:
        2000: {'message': 'No such database file'},
        2001: {'message': 'Incompatible version of SQLite'},
        2002: {'message': 'Maximum attempts exceeded for sqlite3 execute'},
        2003: {'message': 'Error in wazuhdb request',
               'remediation': 'Make sure the request is correct'},
        2004: {'message': 'Database query not valid'},
        2005: {'message': 'Could not connect to wdb socket'},
        2006: {'message': 'Received JSON from Wazuh DB is not correctly formatted'},
        2007: {'message': 'Error retrieving data from Wazuh DB'},
        2008: {'message': 'Corrupted RBAC database',
               'remediation': 'Restart the Wazuh service to restore the RBAC database to default'},

        # Cluster
        3000: 'Cluster',
        3001: 'Error creating zip file',
        3002: {'message': 'Error creating PID file'},
        3003: {'message': 'Error deleting PID file'},
        3004: {'message': 'Error in cluster configuration',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/configuring-cluster/index.html)'
                              ' to get more information about how to configure a cluster'},
        3005: 'Error reading cluster JSON file',
        3006: {'message': 'Error reading cluster configuration',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/configuring-cluster/index.html)'
                              ' to get more information about how to configure a cluster'},
        3007: 'Client.keys file received in master node',
        3008: 'Received invalid agent status',
        3009: {'message': 'Error executing distributed API request',
               'remediation': ''},
        3010: 'Received the status/group of a non-existent agent',
        3011: 'Agent info file received in a worker node',
        3012: 'Cluster is not running',
        3013: {'message': 'Cluster is not running, it might be disabled in `WAZUH_HOME/etc/ossec.conf`',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/configuring-cluster/index.html)'
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
                              f"[ossec.conf](https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/cluster.html#key)"
                              ", ensure it is the same that the master's."},
        3026: "Error sending request: Memory error. Request chunk size divided by 2.",
        3027: "Unknown received task name",
        3028: {'message': "Worker node ID already exists",
               'remediation': f"Check and fix [worker names](https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service."},
        3029: {"message": "Connected worker with same name as the master",
               "remediation": f"Check and fix the [worker name](https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service in the node"},
        3030: {'message': 'Worker does not belong to the same cluster',
               'remediation': f"Change the [cluster name](https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/reference/ossec-conf/cluster.html#name)"
                              " in the worker configuration to match the master's and restart the `wazuh-manager` service"},
        3031: {'message': "Worker and master versions are not the same",
               'remediation': f"[Update](https://documentation.wazuh.com/{WAZUH_VERSION}/upgrade-guide/index.html)"
                              " master and workers to the same version."},
        3032: "Could not forward DAPI request. Connection not available.",
        3033: "Payload length exceeds limit defined in wazuh.cluster.common.Handler.request_chunk.",
        3034: "Error sending file. File not found.",

        # RBAC exceptions
        # The messages of these exceptions are provisional until the RBAC documentation is published.
        4000: {'message': "Permission denied",
               'remediation': "Please, make sure you have permissions to execute the current request. "
                              f"For more information on how to set up permissions, please visit https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/rbac/configuration.html"},
        4001: {'message': 'The body of the request is empty, you must specify what you want to modify'},
        4002: {'message': 'The specified role does not exist',
               'remediation': 'Please, create the specified role with the endpoint POST /security/roles'},
        4003: {'message': 'The specified rule is invalid',
               'remediation': "The rule must be in JSON format."},
        4004: {'message': 'The specified name is invalid'},
        4005: {'message': 'The specified name or rule already exists'},
        4006: {'message': 'The specified policy is invalid',
               'remediation': 'The policy must be in JSON format and its keys must be "actions", "resources" and'
                              ' "effect". The actions and resources must be split by ":". Example: agent:id:001'},
        4007: {'message': 'The specified policy does not exist',
               'remediation': 'Please, create the specified policy with the endpoint POST /security/policies'},
        4008: {'message': 'The specified resource is required for a correct Wazuh\'s functionality'},
        4009: {'message': 'The specified name or policy already exists'},
        4010: {'message': 'The specified role-policy relation does not exist',
               'remediation': 'Please, create the specified role-policy relation with the endpoint '
                              'POST /security/roles/{role_id}/policies'},
        4011: {'message': 'The specified role-policy link already exist'},
        4012: {'message': 'The specified actions or resources are invalid',
               'remediation': 'The actions and resources must be split by ":". Example: agent:id:001'},
        4013: {'message': 'The specified name already exists'},
        4014: {'message': 'Parameter {param} is required',
               'remediation': 'Please, make sure the parameter is defined'},
        4015: {'message': 'Permission denied, could not remove agents from group before deleting it',
               'remediation': 'Please, make sure you have the right permissions for actions: agent:modify_group and '
                              'group:modify_assignments before attempting to delete the group'},
        4016: {'message': 'The specified user-role relation does not exist',
               'remediation': 'Please, create the specified user-role relation with the endpoint '
                              'POST /security/user/{username}/roles'},
        4017: {'message': 'The specified user-role relation already exists'},
        4018: {'message': 'Level cannot be a negative number'},
        4019: {'message': 'Invalid resource specified',
               'remediation': f'Please, check the current RBAC resources, for more information please visit https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/rbac/configuration.html'},
        4020: {'message': 'Invalid endpoint specified',
               'remediation': 'Valid endpoints are: '},
        4021: 'Error reading security configuration',
        4022: {'message': 'The specified security rule does not exist',
               'remediation': 'Please, create the specified security rule with the endpoint POST /security/rules'},
        4023: {'message': 'The specified role-rule relation already exist'},
        4024: {'message': 'The specified role-rule relation does not exist',
               'remediation': 'Please, create the specified role-rules relation with the endpoint '
                              'POST /security/roles/{role_id}/rules'},
        4025: {'message': 'The specify relationship could not be removed'},
        4500: {'message': 'The specified resources are invalid',
               'remediation': 'Please, make sure permissions are properly defined, '
                              f'for more information on setting up permissions please visit https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/rbac/configuration.html'},

        # User management
        5000: {'message': 'The user could not be created',
               'remediation': 'Please check that the user does not exist, '
                              'to do this you can use the `GET /security/users` call'},
        5001: {'message': 'The user does not exist',
               'remediation': 'The user can be created with the endpoint POST /security/users'},
        5002: {'message': 'There are no users in the system'},
        5003: {'message': 'The user could not be modified',
               'remediation': 'There is already a user with these properties'},
        5004: {'message': 'The user could not be removed or updated',
               'remediation': 'Administrator users cannot be removed or updated'},
        5006: {'message': 'Operation not allowed, the user does not have permissions to perform this action',
               'remediation': 'No user, except administrator users, can change the data of a different user'},
        5007: {'message': 'Insecure user password provided',
               'remediation': 'The password must contain at least one upper and lower case letter, a number and a symbol.'},
        5008: {'message': 'The current user cannot be deleted',
               'remediation': 'You can delete this user with the administrator user (wazuh) or '
                              'any other user with the necessary permissions'},
        5009: {'message': 'Insecure user password provided',
               'remediation': 'The password must contain a length between 8 and 64 characters.'},

        # Security issues
        6000: {'message': 'Limit of login attempts reached. '
                          'The current IP has been blocked due to a high number of login attempts'},
        6001: {'message': 'Maximum number of request per minute reached',
               'remediation': f'This limit can be changed in security.yaml file. More information here: https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/configuration.html#configuration-file'},
        6002: {'message': 'The body type is not the one specified in the content-type'},
        6003: {'message': 'Error trying to load the JWT secret',
               'remediation': 'Make sure you have the right permissions: WAZUH_PATH/api/configuration/security/jwt_secret'},
        6004: {'message': 'The current user does not have authentication enabled through authorization context',
               'remediation': f'You can enable it using the following endpoint: https://documentation.wazuh.com/{WAZUH_VERSION}/user-manual/api/configuration.html#configuration-file'},

        # Logtest
        7000: {'message': 'Error trying to get logtest response'},
        7001: {'message': 'Error trying to read logtest session token',
               'remediation': 'Make sure you introduce the token within the field "token"'}

        # > 9000: Authd
    }

    def __init__(self, code, extra_message=None, extra_remediation=None, cmd_error=False, dapi_errors=None, title=None,
                 type=None):
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
        :param title: Name of the exception to be shown
        """
        self._type = type if type else 'about:blank'
        self._title = title if title else self.__class__.__name__
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

        self._remediation = code_remediation if extra_remediation is None \
            else f"{code_remediation}: {extra_remediation}"

    def __str__(self):
        return "Error {0} - {1}".format(self._code, self._message)

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        if not isinstance(other, WazuhException):
            return NotImplemented
        return (self._type,
                self._title,
                self._code,
                self._extra_message,
                self._extra_remediation,
                self._cmd_error) == (other._type,
                                     other._title,
                                     other._code,
                                     other._extra_message,
                                     other._extra_remediation,
                                     other._cmd_error)

    def __hash__(self):
        return hash(
            (self._type, self._title, self._code, self._extra_message, self._extra_remediation, self._cmd_error))

    def __or__(self, other):
        if isinstance(other, WazuhException):
            result = self.__class__(**self.to_dict())
            result.dapi_errors = {**self._dapi_errors, **other.dapi_errors}
        else:
            result = other | self
        return result

    def __deepcopy__(self, memodict=None):
        obj = self.__class__(self.code)
        obj.__dict__ = deepcopy(dict(self.__dict__))
        return obj

    def to_dict(self):
        return {'type': self._type,
                'title': self._title,
                'code': self._code,
                'extra_message': self._extra_message,
                'extra_remediation': self._extra_remediation,
                'cmd_error': self._cmd_error,
                'dapi_errors': self._dapi_errors
                }

    @property
    def type(self):
        return self._type

    @property
    def title(self):
        return self._title

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
    _default_type = "about:blank"
    _default_title = "Wazuh Internal Error"

    def __init__(self, code, extra_message=None, extra_remediation=None, cmd_error=False, dapi_errors=None, ids=None,
                 title=None, type=None):
        """Creates a WazuhInternalError exception.

        :param code: Exception code.
        :param extra_message: Adds an extra message to the error description.
        :param extra_remediation: Adds an extra description to remediation
        :param cmd_error: If it is a custom error code (i.e. ossec commands), the error description will be the message.
        :param dapi_errors: dict with details about node and logfile. I.e.:
                            {'master-node': {'error': 'Wazuh Internal error',
                                             'logfile': WAZUH_HOME/logs/api.log}
                            }
        :param ids: List or set with the ids involved in the exception
        """

        super().__init__(code, extra_message=extra_message,
                         extra_remediation=extra_remediation,
                         cmd_error=cmd_error,
                         dapi_errors=dapi_errors,
                         title=title if title else self._default_title,
                         type=type if type else self._default_type
                         )
        self._ids = set() if ids is None else set(ids)


class WazuhError(WazuhException):
    """
    This type of exception is raised as a controlled response to a bad request from user
    that cannot be performed properly
    """
    _default_type = "about:blank"
    _default_title = "Bad Request"

    def __init__(self, code, extra_message=None, extra_remediation=None, cmd_error=False, dapi_errors=None, ids=None,
                 title=None, type=None):
        """Creates a WazuhError exception.

        :param code: Exception code.
        :param extra_message: Adds an extra message to the error description.
        :param extra_remediation: Adds an extra description to remediation
        :param cmd_error: If it is a custom error code (i.e. ossec commands), the error description will be the message.
        :param dapi_errors: dict with details about node and logfile. I.e.:
                            {'master-node': {'error': 'Wazuh Internal error',
                                             'logfile': WAZUH_HOME/logs/api.log}
                            }
        :param ids: List or set with the ids involved in the exception
        """

        super().__init__(code, extra_message=extra_message,
                         extra_remediation=extra_remediation,
                         cmd_error=cmd_error,
                         dapi_errors=dapi_errors,
                         title=title if title else self._default_title,
                         type=type if type else self._default_type
                         )
        self._ids = set() if ids is None else set(ids)

    @property
    def ids(self):
        return self._ids

    def __or__(self, other):
        result: WazuhError = super().__or__(other)
        if isinstance(result, WazuhError):
            if hasattr(other, 'ids'):
                result._ids = self.ids | other.ids
        return result

    def to_dict(self):
        result = super().to_dict()
        result['ids'] = list(self.ids)

        return result


class WazuhPermissionError(WazuhError):
    """
    This type of exception is raised as a controlled response to a permission denied accessing a resource.
    """
    _default_type = "about:blank"
    _default_title = "Permission Denied"


class WazuhClusterError(WazuhError):
    """
    This type of exception is raised inside the cluster.
    """
    _default_type = "about:blank"
    _default_title = "Wazuh Cluster Error"


class WazuhResourceNotFound(WazuhError):
    """
    This type of exception is raised as a controlled response to a not found resource.
    """
    _default_type = "about:blank"
    _default_title = "Resource Not Found"


class WazuhTooManyRequests(WazuhError):
    """
    This type of exception is raised as a controlled response to too many requests.
    """
    _default_type = "about:blank"
    _default_title = "Too Many Requests"


class WazuhNotAcceptable(WazuhError):
    """
    This type of exception is raised as a controlled response to a not acceptable request
    """
    _default_type = "about:blank"
    _default_title = "Not Acceptable"
