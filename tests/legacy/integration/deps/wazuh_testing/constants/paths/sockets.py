# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from . import WAZUH_PATH


QUEUE_SOCKETS_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets')

ANALYSISD_ANALISIS_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'analysis')
ANALYSISD_QUEUE_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'queue')
AUTHD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'auth')
CLUSTER_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')
EXECD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'com')
LOGCOLLECTOR_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logcollector')
LOGTEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logtest')
MODULESD_WMODULES_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wmodules')
MODULESD_DOWNLOAD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'download')
MODULESD_CONTROL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'control')
MODULESD_KREQUEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'krequest')
MODULESD_C_INTERNAL_SOCKET_PATH = os.path.join(CLUSTER_SOCKET_PATH, 'c-internal.sock')
MONITORD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'monitor')
REMOTED_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'remote')
SYSCHECKD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'syscheck')
WAZUH_DB_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb')

WAZUH_SOCKETS = {
    'wazuh-agentd': [],
    'wazuh-apid': [],
    'wazuh-agentlessd': [],
    'wazuh-csyslogd': [],
    'wazuh-analysisd': [
        ANALYSISD_ANALISIS_SOCKET_PATH,
        ANALYSISD_QUEUE_SOCKET_PATH
    ],
    'wazuh-authd': [AUTHD_SOCKET_PATH],
    'wazuh-execd': [EXECD_SOCKET_PATH],
    'wazuh-logcollector': [LOGCOLLECTOR_SOCKET_PATH],
    'wazuh-monitord': [MONITORD_SOCKET_PATH],
    'wazuh-remoted': [REMOTED_SOCKET_PATH],
    'wazuh-maild': [],
    'wazuh-syscheckd': [SYSCHECKD_SOCKET_PATH],
    'wazuh-db': [WAZUH_DB_SOCKET_PATH],
    'wazuh-modulesd': [
        MODULESD_WMODULES_SOCKET_PATH,
        MODULESD_DOWNLOAD_SOCKET_PATH,
        MODULESD_CONTROL_SOCKET_PATH,
        MODULESD_KREQUEST_SOCKET_PATH
    ],
    'wazuh-clusterd': [MODULESD_C_INTERNAL_SOCKET_PATH]
}
