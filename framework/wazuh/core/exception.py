# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from copy import deepcopy
from typing import Union

from wazuh.core.cluster import __version__
from wazuh.core.common import AGENT_NAME_LEN_LIMIT, MAX_GROUPS_PER_MULTIGROUP, MAX_SOCKET_BUFFER_SIZE

GENERIC_ERROR_MSG = "Wazuh Internal Error. See log for more detail"
DOCU_VERSION = 'current' if __version__ == '' else '.'.join(__version__.split('.')[:2]).lstrip('v')

class WazuhException(Exception):
    """
    Wazuh Exception object.
    """

    ERRORS = {
        # < 999: API
        900: 'One of the API child processes terminated abruptly. The API process pool is not usable anymore. '
             'Please restart the Wazuh API',
        901: 'API executor subprocess broke. A service restart may be needed',
        902: 'API Endpoint only available on master node',

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
               'remediation': 'Please, check if path to file/directory is correct and `wazuh` '
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
        1019: 'Error trying to create backup file',
        1020: {'message': 'Could not find any Wazuh log file',
               'remediation': 'Please check `WAZUH_HOME/logs`'},

        # Configuration: 1100 - 1199
        1101: {'message': 'Requested component does not exist',
               'remediation': 'Run `WAZUH_PATH/bin/wazuh-logtest -t` to check your configuration'},
        1102: {'message': 'Invalid section',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html) '
                              'to get more information about configuration sections'},
        1103: {'message': 'Invalid field in section',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html) '
                              'to get more information about configuration sections'},
        1104: {'message': 'Invalid type',
               'remediation': 'Insert a valid type'},
        1105: 'Error reading API configuration',
        1106: {'message': 'Requested section not present in configuration',
               'remediation': 'Please, check your configuration file. '
                              f'You can visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html) '
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
               'remediation': f"Please, visit the official documentation (https://documentation.wazuh.com/"
                              f"{DOCU_VERSION}/user-manual/api/reference.html#operation/"
                              f"api.controllers.agents_controller.get_agent_config) to check available component "
                              f"configurations"},
        1117: {'message': "Unable to connect with component. The component might be disabled."},
        1118: {'message': "Could not request component configuration"},
        1119: "Directory '/tmp' needs read, write & execution permission for 'wazuh' user",
        1121: {'message': "Error connecting with socket",
               'remediation': "Please ensure the selected module is running and properly configured"},
        1122: {'message': 'Experimental features are disabled',
               'remediation': 'Experimental features can be enabled in WAZUH_PATH/api/configuration/api.yaml'},
        1123: {
            'message': f"Error communicating with socket. Query too long, maximum allowed size for queries is "
                       f"{MAX_SOCKET_BUFFER_SIZE // 1024} KB"},
        1124: {'message': 'Remote command detected',
               'remediation': f'To solve this issue, please enable the remote commands in the API settings or add an '
                              f'exception: https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/'
                              f'configuration.html#remote-commands-localfile-and-wodle-command'},
        1125: {'message': 'Invalid ossec configuration',
               'remediation': 'Please, provide a valid ossec configuration'
               },
        1126: {'message': 'Error updating ossec configuration',
               'remediation': 'Please, ensure `WAZUH_PATH/etc/ossec.conf` has the proper permissions and ownership.'
               },
        1127: {'message': 'Protected section was modified',
               'remediation': 'To solve this, either revert the changes made to this section or disable the protection '
                              'in the API settings: '
                              f"https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/configuration.html"},
        1128: {'message': 'Invalid configuration for the given component'},
        1129: {'message': 'Higher version agents detected',
               'remediation': f'To solve this issue, please enable agents higher versions in the API settings: '
                              f'https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/'
                              f'configuration.html#agents'},
        1130: {'message': 'Public Virus Total API Key detected',
               'remediation': 'To solve this, either use a premium VirusTotal API key or disable the public key'
                              ' protection in the API settings: '
                              f"https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/configuration.html"},
        1131: {'message': 'Virus Total API request error',
               'remediation': 'The use of Virus Total Public API keys is disabled but could not be checked. '
                              'To solve this, check your connection to the Virus Total API or disable the public key'
                              ' protection in the API settings: '
                              f"https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/configuration.html"},
        # Rule: 1200 - 1299
        1200: {'message': 'Error reading rules from `WAZUH_HOME/etc/ossec.conf`',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1201: {'message': 'Error reading rule files',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1202: {'message': 'Argument \'status\' must be: enabled, disabled or all',
               'remediation': 'Please indicate one of the following states: enabled, disabled, all'
               },
        1203: {'message': 'Error in argument \'level\'',
               'remediation': 'Argument \'level\' must be a number or an interval separated by \'-\''
               },
        1205: {'message': 'Requirement not valid',
               'remediation': 'Please indicate one of the following values:'
               },

        1207: {'message': 'Error reading rule files, wrong permissions',
               'remediation': 'Please, check your permissions over the file'
               },
        1208: {'message': 'The rule does not exist or you do not have permission to see it',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about how to configure the rules'
               },
        1209: {'message': 'Invalid relative directory. A \'rule_dir\' tag must '
                          'be declared in ossec.conf ruleset section.',
               'remediation': f'Please, visit the official documentation '
                              f'(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/ruleset.html)'
                              ' to get more information about the rules'
        },
        1210: {'message': 'Uploading, updating or deleting default rules is not allowed.',
               'remediation': f'Please, visit the official documentation '
                              f'(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/ruleset/index.html)'
                              ' to get more information about the rules'
        },
        1211: {'message': 'Invalid relative directory. A \'rule_dir\' tag is declared in ossec.conf '
                          'ruleset section, but the directory does not exist.',
               'remediation': f'Please, visit the official documentation'
                               '(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/ruleset.html)'
                              ' to get more information about the rules'
               },
        1212: {'message': 'Error sending Rules file update to Wazuh-Analysisd'},

        # Stats: 1300 - 1399
        1307: {'message': 'Invalid parameters',
               'remediation': 'Please, check that the update is correct, there is a problem while reading the results, '
                              'contact us at [official repository](https://github.com/wazuh/wazuh/issues)'
               },
        1308: {'message': 'Stats file does not exist',
               'remediation': 'Stats files are usually generated at 12 PM on a daily basis'},
        1309: 'Statistics file damaged',
        1310: {'message': 'Invalid agent ID',
               'remediation': 'This component only exists in real agents'},

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: {'message': 'Invalid sort_ascending field',
               'remediation': 'Please, use only true if ascending or false if descending'
               },
        1403: {'message': 'Not a valid sort field ',
               'remediation': 'Please, use only allowed sort fields'
               },
        1405: {'message': 'Specified limit exceeds maximum allowed',
               'remediation': 'Please select a limit between 1 and 1000'
               },
        1406: {'message': '0 is not a valid limit',
               'remediation': 'Please select a limit between 1 and 1000'
               },
        1407: 'Query does not match expected format',
        1408: 'Field does not exist.',
        1409: 'Invalid query operator',
        1410: 'Selecting more than one field in distinct mode',
        1411: 'TimeFrame is not valid',
        1412: 'Date filter not valid. Valid formats are YYYY-MM-DD HH:mm:ss, YYYY-MM-DDTHH:mm:ssZ or YYYY-MM-DD',
        1413: {'message': 'Error reading rules file'},
        1414: {'message': 'Error reading rules file',
               'remediation': 'Please, make sure you have read permissions over the file'
               },
        1415: {'message': 'Rules file not found',
               'remediation': 'Please, use GET /rules/files to list all available rules'
               },

        # Decoders: 1500 - 1599
        1500: {'message': 'Error reading decoders from ossec.conf',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/ruleset/custom.html)'
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
               'remediation': f'Please, visit the official documentation '
                              f'(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/index.html)'
                              ' to get more information about the decoders'
               },
        1505: {'message': 'Invalid relative directory. A \'decoder_dir\' '
                          'tag must be declared in ossec.conf ruleset section.',
               'remediation': f'Please, visit the official documentation'
                               '(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/ruleset.html)'
                              ' to get more information about the decoders'
               },
        1506: {'message': 'Uploading, updating or deleting default decoders is not allowed.',
               'remediation': f'Please, visit the official documentation'
                               '(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/ruleset/index.html)'
                              ' to get more information about the decoders'
               },
        1507: {'message': 'Invalid relative directory. A \'decoder_dir\' tag is declared '
                          'in ossec.conf ruleset section, but the directory does not exist.',
               'remediation': f'Please, visit the official documentation'
                               '(https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/reference/ossec-conf/ruleset.html)'
                              ' to get more information about the decoders'
               },
        1508: {'message': 'Error sending decoders files update to Wazuh-Analysisd'},

        # Syscheck/AR: 1600 - 1699
        1603: 'Invalid status. Valid statuses are: all, solved and outstanding',
        1650: 'Active response - Command not specified',

        1652: {'message': 'The command used is not defined in the configuration.',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/capabilities/active-response/how-to-configure.html)'
                              'to get more information'
               },

        # Agents: 1700 - 1799
        1701: {'message': 'Agent does not exist',
               'remediation': 'Please, use `GET /agents?select=id,name` to find all available agents'
               },
        1703: {'message': 'Action not available for Manager (agent 000)',
               'remediation': 'Please, use `GET /agents?select=id,name` to find all available agents and make sure you '
                              'select an agent other than 000'
               },
        1705: {'message': 'There is an agent with the same name',
               'remediation': 'Please choose another name'
               },
        1706: {'message': 'There is an agent with the same IP or the IP is invalid',
               'remediation': 'Please choose another IP'
               },
        1707: {'message': 'Cannot send request, agent is not active',
               'remediation': 'Please, check non-active agents connection and try again. Visit '
                              f'https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/registering/index.html and '
                              f'https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/agents/agent-connection.'
                              f'html to obtain more information on registering and connecting agents'
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
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/agents/grouping-agents.html)'
                              'to get more information'
               },
        1713: {'message': 'Invalid group ID. Some IDs are restricted for internal purposes',
               'remediation': 'Please, use another group ID'},
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
        1726: {'message': 'Wazuh authd is not running',
               'remediation': 'Please enable authd or check if there is any error'
               },
        1727: {'message': 'Error listing group files',
               'remediation': 'Please, use `GET /agents/groups/:group_id/files` to get all available group files'
               },
        1728: {'message': 'Invalid node type',
               'remediation': f'Valid types are `master` and `worker`. Please, visit https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/configuring-cluster/index.html '
                              'to get more information about cluster configuration'},
        1730: {'message': 'Node does not exist',
               'remediation': 'Make sure the name is correct and that the node is up. You can check it using '
                              f'`cluster_control -l` (https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/'
                              f'reference/tools/cluster_control.html#get-connected-nodes)'},

        1731: {'message': 'Agent is not eligible for the action to be performed',
               'remediation': 'Please, make sure the agent meets the requirements.'},
        1734: {'message': 'Error removing agent from group',
               'remediation': f'Agent does not belong to specified group, to assign the agent to a group follow: '
                              f'https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/agents/grouping-agents.html'
               },
        1735: {'message': 'Agent version is not compatible with this feature',
               'remediation': 'Please update the agent, in case the problem persists contact us at: https://github.com'
                              '/wazuh/wazuh/issues'
               },
        1737: {'message': f"Maximum number of groups per multigroup is {MAX_GROUPS_PER_MULTIGROUP}",
               'remediation': 'Please choose another group or remove an agent from the target group'
               },
        1738: {'message': 'Agent name is too long',
               'remediation': f'Max length allowed for agent name is {AGENT_NAME_LEN_LIMIT}'
               },
        1740: {'message': 'Action only available for active agents',
               'remediation': 'Please activate the agent to synchronize it'
               },
        1743: 'Error running Wazuh syntax validator',
        1745: "Agent only belongs to 'default' and it cannot be unassigned from this group.",
        1750: {'message': 'Could not send restart command, active-response is disabled in the agent',
               'remediation': "You can activate it in agents' `WAZUH_HOME/etc/ossec.conf`"},
        1751: {'message': 'Could not assign agent to group',
               'remediation': 'Agent already belongs to specified group, please select another agent'},
        1752: {'message': 'Could not force single group for the agent'},
        1757: {'message': 'Error deleting an agent',
               'remediation': 'Please check all data fields and try again'
               },
        1760: {'message': 'Feature only available for older agent versions, it doesn\'t apply for more recent ones.'
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
        1805: {'message': 'File with the same name already exists in a subdirectory.',
               'remediation': 'Please, make sure to use a name which is not repeated. '
               },
        1806: {'message': 'Error trying to create CDB list file.'
               },
        1810: {'message': 'Upgrade module\'s reserved exception IDs (1810-1899). '
                          'The error message will be the output of upgrade module'},
        1811: {'message': 'Error sending CDB list files update to Wazuh-Analysisd'},

        # Manager:
        1901: {'message': '\'execq\' socket has not been created'
               },
        1902: {'message': 'Connection to \'execq\' socket failed'
               },
        1904: {'message': 'Bad data from \'wcom\''
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
        1910: {'message': 'Content-type header is mandatory',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/api/reference.html#operation/api.controllers.'
                              f'cluster_controller.put_files_node)'
                              ' to get more information about how to configure a cluster'},
        1911: {'message': 'Error parsing body request to UTF-8',
               'remediation': 'Please, check if the file content is valid UTF-8'},
        1912: {'message': 'Body is empty',
               'remediation': 'Please, check the content of the file to be uploaded'},
        1913: {'message': 'Error getting manager status, directory /proc is not found or permissions to see its status '
                          'are not granted',
               'remediation': 'Please, ensure /proc exists and permissions are granted'},

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
        2009: {'message': 'Pagination error. Response from wazuh-db was over the maximum socket buffer size'},
        2010: {'message': 'The requested read operation did not complete fully'},
        2011: {'message': 'Could not connect to the wazuh-db unix socket'},
        2012: {'message': 'Invalid wazuh-db HTTP request'},
        2013: {'message': 'Error sending HTTP request'},
        2014: {'message': 'The wazuh-db client connection timeout has been exceeded'},
        2015: {'message': 'Invalid request URL scheme'},
        2016: {'message': 'Invalid unix socket path'},

        # Engine API client
        2800: {'message': 'The engine client connection timeout has been exceeded'},
        2801: {'message': 'Invalid request URL scheme'},
        2802: {'message': 'Invalid unix socket path'},
        2803: {'message': 'Error sending request to the engine'},
        2804: {'message': 'Unexpected error sending request to the engine'},
        2805: {'message': 'Error parsing response from the engine'},

        # External services
        2100: {'message': 'Error in CTI service request'},

        # Cluster
        3000: 'Cluster',
        3001: 'Error creating zip file',
        3002: {'message': 'Error creating PID file'},
        3004: {'message': 'Error in cluster configuration',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/configuring-cluster/index.html)'
                              ' to get more information about how to configure a cluster'},
        3005: 'Error reading cluster JSON file',
        3006: {'message': 'Error reading cluster configuration',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/configuring-cluster/index.html)'
                              ' to get more information about how to configure a cluster'},
        3007: 'Client.keys file received in master node',
        3009: {'message': 'Error executing distributed API request',
               'remediation': ''},
        3012: 'Cluster is not running',
        3013: {'message': 'Cluster is not running, it might be disabled in `WAZUH_HOME/etc/ossec.conf`',
               'remediation': f'Please, visit the official documentation (https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/configuring-cluster/index.html)'
                              ' to get more information about how to configure a cluster'
               },
        3015: 'Cannot access directory',
        3016: 'Received an error response',
        3018: 'Error sending request',
        3019: 'Wazuh is running in cluster mode: {EXECUTABLE_NAME} is not available in worker nodes. Please, '
              'try again in the master node: {MASTER_IP}',
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
                              f"[ossec.conf](https://documentation.wazuh.com/{DOCU_VERSION}/user-manual/reference/"
                              f"ossec-conf/cluster.html#key)"
                              ", ensure it is the same that the master's."},
        3026: "Error sending request: Memory error. Request chunk size divided by 2.",
        3027: "Unknown received task name",
        3028: {'message': "Worker node ID already exists",
               'remediation': f"Check and fix [worker names](https://documentation.wazuh.com/{DOCU_VERSION}/"
                              f"user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service."},
        3029: {"message": "Connected worker with same name as the master",
               "remediation": f"Check and fix the [worker name](https://documentation.wazuh.com/{DOCU_VERSION}/"
                              f"user-manual/reference/ossec-conf/cluster.html#node-name)"
                              " and restart the `wazuh-manager` service in the node"},
        3030: {'message': 'Worker does not belong to the same cluster',
               'remediation': f"Change the [cluster name](https://documentation.wazuh.com/{DOCU_VERSION}/"
                              f"user-manual/reference/ossec-conf/cluster.html#name)"
                              " in the worker configuration to match the master's and restart the `wazuh-manager` "
                              "service"},
        3031: {'message': "Worker and master versions are not the same",
               'remediation': f"[Update](https://documentation.wazuh.com/{DOCU_VERSION}/upgrade-guide/index.html)"
                              " master and workers to the same version."},
        3032: "Could not forward DAPI request. Connection not available.",
        3034: "Error sending file. File not found.",
        3035: "String couldn't be found",
        3036: "JSON couldn't be loaded",
        3037: 'Error while processing Agent-info chunks',
        3038: "Error while processing extra-valid files",
        3039: "Timeout while waiting to receive a file",
        3040: "Error while waiting to receive a file",

        # HAProxy Helper exceptions
        3041: "Server status check timed out after adding new servers",
        3042: "User configuration is not valid",
        3043: "Could not initialize Proxy API",
        3044: "Could not connect to the HAProxy dataplane API",
        3045: "Could not connect to HAProxy",
        3046: "Invalid credentials for the Proxy API",
        3047: "Invalid HAProxy Dataplane API specification configured",
        3048: "Could not detect a valid HAProxy process linked to the Dataplane API",
        3049: "Unexpected response from HAProxy Dataplane API",

        # RBAC exceptions
        # The messages of these exceptions are provisional until the RBAC documentation is published.
        4000: {'message': "Permission denied",
               'remediation': "Please, make sure you have permissions to execute the current request. "
                              f"For more information on how to set up permissions, please visit https://documentation."
                              f"wazuh.com/{DOCU_VERSION}/user-manual/api/rbac/configuration.html"},
        4001: {'message': 'The body of the request is empty, you must specify what you want to modify'},
        4002: {'message': 'The specified role does not exist',
               'remediation': 'Please, create the specified role with the endpoint POST /security/roles'},
        4003: {'message': 'The specified rule is invalid',
               'remediation': "The rule must be in JSON format."},
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
        4013: {'message': 'The specified name already exists'},
        4016: {'message': 'The specified user-role relation does not exist',
               'remediation': 'Please, create the specified user-role relation with the endpoint '
                              'POST /security/user/{username}/roles'},
        4017: {'message': 'The specified user-role relation already exists'},
        4018: {'message': 'Level cannot be a negative number'},
        4019: {'message': 'Invalid resource specified',
               'remediation': f'Please, check the current RBAC resources, for more information please visit https:/'
                              f'/documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/rbac/configuration.html'},
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
                              f'for more information on setting up permissions please visit https://documentation.'
                              f'wazuh.com/{DOCU_VERSION}/user-manual/api/rbac/configuration.html'},

        # User management
        5000: {'message': 'The user could not be created',
               'remediation': 'Please check that the user does not exist, '
                              'to do this you can use the `GET /security/users` call'},
        5001: {'message': 'The user does not exist',
               'remediation': 'The user can be created with the endpoint POST /security/users'},
        5004: {'message': 'The user could not be removed or updated',
               'remediation': 'Administrator users cannot be removed or updated'},
        5007: {'message': 'Insecure user password provided',
               'remediation': 'The password must contain at least one upper and lower case letter, a number and a '
                              'symbol.'},
        5008: {'message': 'The current user cannot be deleted',
               'remediation': 'You can delete this user with the administrator user (wazuh) or '
                              'any other user with the necessary permissions'},
        5009: {'message': 'Insecure user password provided',
               'remediation': 'The password must contain a length between 8 and 64 characters.'},
        5010: {'message': 'The value of the parameter allow_run_as is invalid',
               'remediation': 'The value of the allow_run_as parameter must be true (enabled authentication through '
                              'authorization context) or false (disabled authentication through authorization context).'
               },
        5011: {'message': 'Administrator users can only be modified by themselves',
               'remediation': 'Log in as administrator and try again'},

        # Security issues
        6000: {'message': 'Limit of login attempts reached. '
                          'The current IP has been blocked due to a high number of login attempts'},
        6001: {'message': 'Maximum number of requests per minute reached',
               'remediation': f'This limit can be changed in api.yaml file. More information here: https:/'
                              f'/documentation.wazuh.com/{DOCU_VERSION}/user-manual/api/configuration.html#'
                              f'configuration-file'},
        6002: {'message': 'The body type is not the one specified in the content-type'},
        6003: {'message': 'Error trying to load the JWT secret',
               'remediation': 'Make sure you have the right permissions: WAZUH_PATH/api/configuration/security/'
                              'jwt_secret'},
        6004: {'message': 'The current user does not have authentication enabled through authorization context',
               'remediation': f'You can enable it using the following endpoint: https://documentation.wazuh.com/'
                              f'{DOCU_VERSION}/user-manual/api/reference.html#operation/api.controllers.'
                              f'security_controller.edit_run_as'},
        6005: {'message': 'Maximum number of requests per minute reached'},

        # Logtest
        7000: {'message': 'Error trying to get logtest response'},
        7001: {'message': 'Error trying to read logtest session token',
               'remediation': 'Make sure you introduce the token within the field "token"'},

    }

    # Reserve agent upgrade custom errors
    ERRORS.update({key: {'message': 'Vulnerability scan\'s reserved exception IDs (8001-9000). '
                                    'The error message will be the output of vulnerability scan module'}
                   for key in range(8001, 9000)})

    def __init__(self, code: int, extra_message: str = None, extra_remediation: str = None, cmd_error: bool = False,
                 dapi_errors: dict = None, title: str = None, type: str = None):
        """Create a WazuhException object.

        Parameters
        ----------
        code : int
            Exception code.
        extra_message : str
            Adds an extra message to the error description.
        extra_remediation : str
            Adds an extra description to remediation.
        cmd_error : bool
            If it is a custom error code (i.e. ossec commands), the error description will be the message.
        dapi_errors : dict
            Dictionary with details about node and logfile. I.e.: {'master-node': {'error': 'Wazuh Internal error',
            'logfile': WAZUH_HOME/logs/api.log}}
        title : str
            Name of the exception to be shown.
        type : str
            Type of the exception.
        """
        self._type = type if type else 'about:blank'
        self._title = title if title else self.__class__.__name__
        self._code = code
        self._extra_message = extra_message
        self._extra_remediation = extra_remediation
        self._cmd_error = cmd_error
        self._dapi_errors = {} if dapi_errors is None else deepcopy(dapi_errors)

        if not cmd_error and self._code in self.ERRORS:
            error_details = self.ERRORS[self._code]
            if isinstance(error_details, dict):
                code_message, code_remediation = error_details.get('message', ''), error_details.get('remediation', None)
            else:
                code_message, code_remediation = error_details, None

            if extra_message:
                if isinstance(extra_message, dict):
                    self._message = code_message.format(**extra_message)
                else:
                    self._message = f"{code_message}: {extra_message}"
            else:
                self._message = code_message
            self._remediation = code_remediation if extra_remediation is None \
                else f"{code_remediation}: {extra_remediation}"
        else:
            self._message = extra_message
            self._remediation = None

    def __str__(self):
        return f"Error {self._code} - {self._message}"

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

    def to_dict(self) -> dict:
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

    def __init__(self, code: int, extra_message: str = None, extra_remediation: str = None, cmd_error: bool = False,
                 dapi_errors: dict = None, ids: Union[list, set] = None, title: str = None, type: str = None):
        """Create a WazuhInternalError exception.

        Parameters
        ----------
        code : int
            Exception code.
        extra_message : str
            Adds an extra message to the error description.
        extra_remediation : str
            Adds an extra description to remediation.
        cmd_error : bool
            If it is a custom error code (i.e. ossec commands), the error description will be the message.
        dapi_errors : dict
            Dictionary with details about node and logfile. I.e.: {'master-node': {'error': 'Wazuh Internal error',
            'logfile': WAZUH_HOME/logs/api.log}}
        title : str
            Name of the exception to be shown.
        type : str
            Type of the exception.
        ids : list or set
            List or set with the ids involved in the exception
        """

        super().__init__(code, extra_message=extra_message,
                         extra_remediation=extra_remediation,
                         cmd_error=cmd_error,
                         dapi_errors=dapi_errors,
                         title=title if title else self._default_title,
                         type=type if type else self._default_type
                         )
        self._ids = set() if ids is None else set(ids)


class WazuhClusterError(WazuhInternalError):
    """
    This type of exception is raised inside the cluster.
    """
    _default_type = "about:blank"
    _default_title = "Wazuh Cluster Error"


class WazuhHAPHelperError(WazuhClusterError):
    """
    This type of exception is raised inside the HAProxy Helper.
    """
    _default_type = "about:blank"
    _default_title = "HAProxy Helper Error"


class WazuhEngineError(WazuhInternalError):
    """
    This type of exception is raised inside the engine client.
    """
    _default_type = "about:blank"
    _default_title = "Wazuh Engine Error"


class WazuhError(WazuhException):
    """
    This type of exception is raised as a controlled response to a bad request from user
    that cannot be performed properly.
    """
    _default_type = "about:blank"
    _default_title = "Bad Request"

    def __init__(self, code: int, extra_message: str = None, extra_remediation: str = None, cmd_error: bool = False,
                 dapi_errors: dict = None, ids: Union[list, set] = None, title: str = None, type: str = None):
        """Create a WazuhError exception.

        Parameters
        ----------
        code : int
            Exception code.
        extra_message : str
            Adds an extra message to the error description.
        extra_remediation : str
            Adds an extra description to remediation.
        cmd_error : bool
            If it is a custom error code (i.e. ossec commands), the error description will be the message.
        dapi_errors : dict
            Dictionary with details about node and logfile. I.e.: {'master-node': {'error': 'Wazuh Internal error',
            'logfile': WAZUH_HOME/logs/api.log}}
        title : str
            Name of the exception to be shown.
        type : str
            Type of the exception.
        ids : list or set
            List or set with the ids involved in the exception
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

    def to_dict(self) -> dict:
        result = super().to_dict()
        result['ids'] = list(self.ids)

        return result


class WazuhPermissionError(WazuhError):
    """
    This type of exception is raised as a controlled response to a permission denied accessing a resource.
    """
    _default_type = "about:blank"
    _default_title = "Permission Denied"


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
