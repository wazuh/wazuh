# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from contextvars import ContextVar
from copy import deepcopy
from functools import lru_cache, wraps
from grp import getgrnam
from multiprocessing import Event
from pwd import getpwnam
from typing import Any, Dict


# ----------------------------------------------------------------------------------------------------------------------
# ===================================================== Functions ======================================================
# ----------------------------------------------------------------------------------------------------------------------
@lru_cache(maxsize=None)
def find_wazuh_path() -> str:
    """
    Get the Wazuh installation path.

    Returns
    -------
    str
        Path where Wazuh is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    wazuh_path = ''
    try:
        for i in range(0, allparts.index('framework')):
            wazuh_path = os.path.join(wazuh_path, allparts[i])
    except ValueError:
        pass

    return wazuh_path


def wazuh_uid():
    """_summary_

    Returns
    -------
    _type_
        _description_
    """
    return getpwnam(USER_NAME).pw_uid if globals()['_wazuh_uid'] is None else globals()['_wazuh_uid']


def wazuh_gid():
    """_summary_

    Returns
    -------
    _type_
        _description_
    """
    return getgrnam(GROUP_NAME).gr_gid if globals()['_wazuh_gid'] is None else globals()['_wazuh_gid']


def context_cached(key: str = '') -> Any:
    """Save the result of the decorated function in a cache.

    Next calls to the decorated function returns the saved result saving time and resources. The cache gets
    invalidated at the end of the request.

    Parameters
    ----------
    key : str
        Part of the cache entry identifier. The identifier will be the key + args + kwargs.

    Returns
    -------
    Any
        The result of the first call to the decorated function.

    Notes
    -----
    The returned object will be a deep copy of the cached one.
    """

    def decorator(func) -> Any:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            cached_key = json.dumps({'key': key, 'args': args, 'kwargs': kwargs})
            if cached_key not in _context_cache:
                _context_cache[cached_key] = ContextVar(cached_key, default=None)
            if _context_cache[cached_key].get() is None:
                result = func(*args, **kwargs)
                _context_cache[cached_key].set(result)
            return deepcopy(_context_cache[cached_key].get())

        return wrapper

    return decorator


def reset_context_cache() -> None:
    """Reset context cache."""

    for context_var in _context_cache.values():
        context_var.set(None)


def get_context_cache() -> dict:
    """Get the context cache.

    Returns
    -------
    dict
        Dictionary with the context variables representing the cache.
    """

    return _context_cache


# ----------------------------------------------------------------------------------------------------------------------
# ================================================= Context variables ==================================================
# ----------------------------------------------------------------------------------------------------------------------
rbac: ContextVar[Dict] = ContextVar('rbac', default={'rbac_mode': 'black'})
current_user: ContextVar[str] = ContextVar('current_user', default='')
broadcast: ContextVar[bool] = ContextVar('broadcast', default=False)
cluster_nodes: ContextVar[list] = ContextVar('cluster_nodes', default=list())
origin_module: ContextVar[str] = ContextVar('origin_module', default='framework')
try:
    mp_pools: ContextVar[Dict] = ContextVar('mp_pools', default={
        'process_pool': ProcessPoolExecutor(max_workers=1),
        'authentication_pool': ProcessPoolExecutor(max_workers=1)
    })
# Handle exception when the user running Wazuh cannot access /dev/shm
except (FileNotFoundError, PermissionError):
    mp_pools: ContextVar[Dict] = ContextVar('mp_pools', default={
        'thread_pool': ThreadPoolExecutor(max_workers=1)
    })
_context_cache = dict()


# ----------------------------------------------------------------------------------------------------------------------
# ================================================= Metadata variables =================================================
# ----------------------------------------------------------------------------------------------------------------------
try:
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, 'wazuh.json'), 'r') as f:
        metadata = json.load(f)
except (FileNotFoundError, PermissionError):
    metadata = {
        'install_type': 'server',
        'installation_date': '',
        'wazuh_version': ''
    }
install_type = metadata['install_type']
wazuh_version = metadata['wazuh_version']
installation_date = metadata['installation_date']


# ----------------------------------------------------------------------------------------------------------------------
# ================================================== Wazuh constants ===================================================
# ----------------------------------------------------------------------------------------------------------------------
USER_NAME = 'wazuh'
GROUP_NAME = 'wazuh'
_wazuh_uid = None
_wazuh_gid = None
wazuh_path = find_wazuh_path()
# Clear cache event.
cache_event = Event()


# ----------------------------------------------------------------------------------------------------------------------
# ============================================= Wazuh constants - Command ==============================================
# ----------------------------------------------------------------------------------------------------------------------
CHECK_CONFIG_COMMAND = 'check-manager-configuration'
RESTART_WAZUH_COMMAND = 'restart-wazuh'


# ----------------------------------------------------------------------------------------------------------------------
# =============================================== Wazuh constants - Date ===============================================
# ----------------------------------------------------------------------------------------------------------------------
date_format = "%Y-%m-%dT%H:%M:%SZ"
decimals_date_format = "%Y-%m-%dT%H:%M:%S.%fZ"


# ----------------------------------------------------------------------------------------------------------------------
# ============================================= Wazuh constants - Ruleset ==============================================
# ----------------------------------------------------------------------------------------------------------------------
RULES_EXTENSION = '.xml'
DECODERS_EXTENSION = '.xml'
LISTS_EXTENSION = ''
COMPILED_LISTS_EXTENSION = '.cdb'


# ----------------------------------------------------------------------------------------------------------------------
# =============================================== Wazuh constants - Size ===============================================
# ----------------------------------------------------------------------------------------------------------------------
MAX_SOCKET_BUFFER_SIZE = 64 * 1024  # 64KB
MAX_QUERY_FILTERS_RESERVED_SIZE = MAX_SOCKET_BUFFER_SIZE - 4 * 1024  # MAX_BUFFER_SIZE - 4KB
agent_name_len_limit = 128
database_limit = 500
maximum_database_limit = 100000
max_groups_per_multigroup = 256


# ----------------------------------------------------------------------------------------------------------------------
# ============================================= Wazuh constants - Version ==============================================
# ----------------------------------------------------------------------------------------------------------------------
# Agent upgrading variables.
wpk_repo_url_4_x = "packages.wazuh.com/4.x/wpk/"
# Agent component stats required version.
AGENT_COMPONENT_STATS_REQUIRED_VERSION = {'logcollector': 'v4.2.0', 'agent': 'v4.2.0'}
# Version variables (legacy, required, etc).
AR_LEGACY_VERSION = 'Wazuh v4.2.0'
ACTIVE_CONFIG_VERSION = 'Wazuh v3.7.0'


# ----------------------------------------------------------------------------------------------------------------------
# ================================================ Wazuh path - Config =================================================
# ----------------------------------------------------------------------------------------------------------------------
ossec_conf = os.path.join(wazuh_path, 'etc', 'ossec.conf')
internal_options = os.path.join(wazuh_path, 'etc', 'internal_options.conf')
local_internal_options = os.path.join(wazuh_path, 'etc', 'local_internal_options.conf')
ar_conf_path = os.path.join(wazuh_path, 'etc', 'shared', 'ar.conf')
client_keys = os.path.join(wazuh_path, 'etc', 'client.keys')
shared_path = os.path.join(wazuh_path, 'etc', 'shared')
ossec_log = os.path.join(wazuh_path, 'logs', 'ossec.log')


# ----------------------------------------------------------------------------------------------------------------------
# ================================================= Wazuh path - Misc ==================================================
# ----------------------------------------------------------------------------------------------------------------------
stats_path = os.path.join(wazuh_path, 'stats')
backup_path = os.path.join(wazuh_path, 'backup')
multi_groups_path = os.path.join(wazuh_path, 'var', 'multigroups')
database_path = os.path.join(wazuh_path, 'var', 'db')
database_path_global = os.path.join(database_path, 'global.db')
database_path_agents = os.path.join(database_path, 'agents')
os_pidfile = os.path.join('var', 'run')
analysisd_stats = os.path.join(wazuh_path, 'var', 'run', 'wazuh-analysisd.state')
remoted_stats = os.path.join(wazuh_path, 'var', 'run', 'wazuh-remoted.state')
pidfiles_path = os.path.join(wazuh_path, 'var', 'run')
tmp_path = os.path.join(wazuh_path, 'tmp')


# ----------------------------------------------------------------------------------------------------------------------
# =========================================== Wazuh path - Queue and socket ============================================
# ----------------------------------------------------------------------------------------------------------------------
ARQUEUE = os.path.join(wazuh_path, 'queue', 'alerts', 'ar')
EXECQ = os.path.join(wazuh_path, 'queue', 'alerts', 'execq')
wdb_path = os.path.join(wazuh_path, 'queue', 'db')
wdb_socket_path = os.path.join(wazuh_path, 'queue', 'db', 'wdb')
groups_path = os.path.join(wazuh_path, 'queue', 'agent-groups')
AUTHD_SOCKET = os.path.join(wazuh_path, 'queue', 'sockets', 'auth')
WCOM_SOCKET = os.path.join(wazuh_path, 'queue', 'sockets', 'com')
LOGTEST_SOCKET = os.path.join(wazuh_path, 'queue', 'sockets', 'logtest')
UPGRADE_SOCKET = os.path.join(wazuh_path, 'queue', 'tasks', 'upgrade')
TASKS_SOCKET = os.path.join(wazuh_path, 'queue', 'tasks', 'task')


# ----------------------------------------------------------------------------------------------------------------------
# ================================================ Wazuh path - Ruleset ================================================
# ----------------------------------------------------------------------------------------------------------------------
ruleset_path = os.path.join(wazuh_path, 'ruleset')
ruleset_rules_path = os.path.join(ruleset_path, 'rules')
ruleset_decoders_path = os.path.join(ruleset_path, 'decoders')
ruleset_lists_path = os.path.join(ruleset_path, 'lists')
user_lists_path = os.path.join(wazuh_path, 'etc', 'lists')
user_rules_path = os.path.join(wazuh_path, 'etc', 'rules')
user_decoders_path = os.path.join(wazuh_path, 'etc', 'decoders')
