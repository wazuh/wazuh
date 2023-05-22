# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


AGENT_DAEMON = 'wazuh-agentd'
AGENTLESS_DAEMON = 'wazuh-agentlessd'
ANALYSISD_DAEMON = 'wazuh-analysisd'
API_DAEMON = 'wazuh-apid'
CLUSTER_DAEMON = 'wazuh-clusterd'
CSYSLOG_DAEMON = 'wazuh-csyslogd'
EXEC_DAEMON = 'wazuh-execd'
INTEGRATOR_DAEMON = 'wazuh-integratord'
MAIL_DAEMON = 'wazuh-maild'
MODULES_DAEMON = 'wazuh-modulesd'
MONITOR_DAEMON = 'wazuh-monitord'
LOGCOLLECTOR_DAEMON = 'wazuh-logcollector'
REMOTE_DAEMON = 'wazuh-remoted'
SYSCHECK_DAEMON = 'wazuh-syscheckd'
WAZUH_DB_DAEMON = 'wazuh-db'

WAZUH_AGENT_DAEMONS = [AGENT_DAEMON,
                       EXEC_DAEMON,
                       MODULES_DAEMON,
                       LOGCOLLECTOR_DAEMON,
                       SYSCHECK_DAEMON]

WAZUH_MANAGER_DAEMONS = [AGENTLESS_DAEMON,
                         ANALYSISD_DAEMON,
                         API_DAEMON,
                         CLUSTER_DAEMON,
                         CSYSLOG_DAEMON,
                         EXEC_DAEMON,
                         INTEGRATOR_DAEMON,
                         LOGCOLLECTOR_DAEMON,
                         MAIL_DAEMON,
                         MODULES_DAEMON,
                         MONITOR_DAEMON,
                         REMOTE_DAEMON,
                         SYSCHECK_DAEMON,
                         WAZUH_DB_DAEMON]

API_DAEMONS_REQUIREMENTS = [ANALYSISD_DAEMON,
                            API_DAEMON,
                            EXEC_DAEMON,
                            MODULES_DAEMON,
                            REMOTE_DAEMON,
                            WAZUH_DB_DAEMON]

WAZUH_UNIX_USER = 'wazuh'
WAZUH_UNIX_GROUP = 'wazuh'
