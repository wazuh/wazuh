#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from itertools import chain
from operator import itemgetter

# API Messages
list_requests_agents = {
    'RESTART_AGENTS'        : 'restart',
    'AGENTS_UPGRADE_RESULT' : 'agents_upg_result',
    'AGENTS_UPGRADE'        : 'agents_upg',
    'AGENTS_UPGRADE_CUSTOM' : 'agents_upg_custom'
}

list_requests_syscheck = {
    'SYSCHECK_LAST_SCAN'    : 'syscheck_last',
    'SYSCHECK_RUN'          : 'syscheck_run',
    'SYSCHECK_CLEAR'        : 'syscheck_clear'
}

list_requests_rootcheck = {
    'ROOTCHECK_LAST_SCAN'   : 'rootcheck_last',
    'ROOTCHECK_PCI'         : 'rootcheck_pci',
    'ROOTCHECK_CIS'         : 'rootcheck_cis',
    'ROOTCHECK_RUN'         : 'rootcheck_run',
    'ROOTCHECK_CLEAR'       : 'rootcheck_clear'
}

list_requests_managers = {
    'MANAGERS_STATUS'       : 'manager_status',
    'MANAGERS_LOGS'         : 'manager_logs',
    'MANAGERS_LOGS_SUMMARY' : 'manager_logs_sum',
    'MANAGERS_STATS_TOTALS' : 'manager_stats_to',
    'MANAGERS_STATS_WEEKLY' : 'manager_stats_we',
    'MANAGERS_STATS_HOURLY' : 'manager_stats_ho',
    'MANAGERS_OSSEC_CONF'   : 'manager_ossec_conf',
    'MANAGERS_INFO'         : 'manager_info'
}

list_requests_cluster = {
    'CLUSTER_CONFIG'        : 'cluster_config',
    'MASTER_FORW'           : 'master_forward',
    'zip'                   : 'zip',
    'node'                  : 'node',
    'ready'                 : 'ready',
    'data'                  : 'data',
    'sendme'                : 'sendme'
}

# All dicts that start with "list_requests"
all_list_requests = dict(chain.from_iterable(map(lambda x: x.items(),
                    map(itemgetter(1), filter(lambda x:
                    x[0].startswith('list_requests'), locals().items())))))
