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
from pathlib import Path
from pwd import getpwnam
from typing import Any, Dict


# ===================================================== Functions ======================================================
@lru_cache(maxsize=None)
def find_wazuh_path() -> str:
    """Get the Wazuh installation path.

    Returns
    -------
    str
        Path where Wazuh is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths.
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths.
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


def wazuh_uid() -> int:
    """Retrieve the numerical user ID for the wazuh user.

    Returns
    -------
    int
        Numerical user ID.
    """
    return getpwnam(USER_NAME).pw_uid if globals()['_WAZUH_UID'] is None else globals()['_WAZUH_UID']


def wazuh_gid() -> int:
    """Retrieve the numerical group ID for the wazuh group.

    Returns
    -------
    int
        Numerical group ID.
    """
    return getgrnam(GROUP_NAME).gr_gid if globals()['_WAZUH_GID'] is None else globals()['_WAZUH_GID']


def async_context_cached(key: str = '') -> Any:
    """Save the result of the asynchronous decorated function in a cache.

    Next calls to the asynchronous decorated function returns the saved result saving time and resources. The cache gets
    invalidated at the end of the request.

    Parameters
    ----------
    key : str
        Part of the cache entry identifier. The identifier will be the key + args + kwargs.

    Returns
    -------
    Any
        The result of the first call to the asynchronous decorated function.

    Notes
    -----
    The returned object will be a deep copy of the cached one.
    """

    def decorator(func) -> Any:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            cached_key = json.dumps({'key': key, 'args': args, 'kwargs': kwargs})
            if cached_key not in _context_cache:
                _context_cache[cached_key] = ContextVar(cached_key, default=None)
            if _context_cache[cached_key].get() is None:
                result = await func(*args, **kwargs)
                _context_cache[cached_key].set(result)
            return deepcopy(_context_cache[cached_key].get())

        return wrapper

    return decorator


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


# ================================================= Context variables ==================================================
rbac: ContextVar[Dict] = ContextVar('rbac', default={'rbac_mode': 'black'})
rbac_manager: ContextVar[Any] = ContextVar('rbac_manager', default=None)
current_user: ContextVar[str] = ContextVar('current_user', default='')
broadcast: ContextVar[bool] = ContextVar('broadcast', default=False)
origin_module: ContextVar[str] = ContextVar('origin_module', default='framework')
try:
    mp_pools: ContextVar[Dict] = ContextVar(
        'mp_pools',
        default={
            'process_pool': ProcessPoolExecutor(max_workers=1),
            'authentication_pool': ProcessPoolExecutor(max_workers=1),
        },
    )
# Handle exception when the user running Wazuh cannot access /dev/shm.
except (FileNotFoundError, PermissionError):
    mp_pools: ContextVar[Dict] = ContextVar('mp_pools', default={'thread_pool': ThreadPoolExecutor(max_workers=1)})
_context_cache = dict()


# =========================================== Wazuh constants and variables ============================================
# Clear cache event.
cache_event = Event()
_WAZUH_UID = None
_WAZUH_GID = None
GROUP_NAME = 'wazuh-server'
USER_NAME = 'wazuh-server'

# TODO: Keep until we remove the different deprecated functionalities that are importing it.
WAZUH_PATH = ''

USR_ROOT = Path('/usr')
ETC_ROOT = Path('/etc')
RUN_ROOT = Path('/run')
VAR_ROOT = Path('/var')
BIN_ROOT = Path('/bin')

USR_SHARE = USR_ROOT / Path('share')
VAR_LOG = VAR_ROOT / Path('log')
VAR_LIB = VAR_ROOT / Path('lib')

WAZUH_SERVER = 'wazuh-server'
WAZUH_SHARE = USR_SHARE / WAZUH_SERVER
WAZUH_ETC = ETC_ROOT / WAZUH_SERVER
WAZUH_RUN = RUN_ROOT / WAZUH_SERVER
WAZUH_LOG = VAR_LOG / WAZUH_SERVER
WAZUH_LIB = VAR_LIB / WAZUH_SERVER

WAZUH_GROUPS = WAZUH_ETC / 'groups'

CONFIG_SERVER_SOCKET = 'config-server.sock'
CONFIG_SERVER_SOCKET_PATH = WAZUH_RUN / CONFIG_SERVER_SOCKET

COMMS_API_SOCKET = 'comms-api.sock'
COMMS_API_SOCKET_PATH = WAZUH_RUN / COMMS_API_SOCKET
MANAGEMENT_API_SOCKET = 'management-api.sock'
MANAGEMENT_API_SOCKET_PATH = WAZUH_RUN / MANAGEMENT_API_SOCKET


# ============================================= Wazuh constants - Commands =============================================
CHECK_CONFIG_COMMAND = 'check-manager-configuration'
RESTART_WAZUH_COMMAND = 'restart-wazuh'


# =========================================== Wazuh constants - Date format ============================================
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DECIMALS_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


# ========================================= Wazuh constants - Size and limits ==========================================
MAX_SOCKET_BUFFER_SIZE = 64 * 1024  # 64KB.
MAX_QUERY_FILTERS_RESERVED_SIZE = MAX_SOCKET_BUFFER_SIZE - 4 * 1024  # MAX_BUFFER_SIZE - 4KB.
AGENT_NAME_LEN_LIMIT = 128
DATABASE_LIMIT = 500
MAXIMUM_DATABASE_LIMIT = 100000


# ================================================ Wazuh path - Config =================================================
WAZUH_SERVER_YML = WAZUH_ETC / 'wazuh-server.yml'
WAZUH_INDEXER_CA_BUNDLE = WAZUH_ETC / 'certs' / 'root-ca-merged.pem'

# ================================================= Wazuh path - Misc ==================================================
DEFAULT_RBAC_RESOURCES = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'rbac', 'default')

# TODO: Constants asociate to functionality next to deprecate.
WAZUH_LOG_JSON = os.path.join('', 'ossec.json')
WDB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')


# ================================================ Wazuh path - Sockets ================================================
ENGINE_SOCKET = WAZUH_RUN / 'engine.socket'
# TODO: Constants asociated to functionality next to deprecate.
AR_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'alerts', 'ar')
EXECQ_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'alerts', 'execq')
AUTHD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'auth')
WCOM_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'com')
REMOTED_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'remote')
WDB_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb')
