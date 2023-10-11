# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import ssl
import uuid
from functools import wraps
from typing import AsyncGenerator, Callable

import aiohttp
import certifi
from aiohttp import web

import wazuh
from api.constants import INSTALLATION_UID_KEY, INSTALLATION_UID_PATH, UPDATE_INFORMATION_KEY
from wazuh.core import common
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.requests import query_update_check_service


ONE_DAY_SLEEP = 60*60*24
UPDATE_CHECK_OSSEC_FIELD = 'update_check'

logger = logging.getLogger('wazuh-api')


def cancel_signal_handler(func: Callable) -> Callable:
    """Decorator to handle asyncio.CancelledError for signals coroutines.

    Parameters
    ----------
    func : Callable
        Coroutine to handle.

    Returns
    -------
    Callable
        Wrapped coroutine with exception handled.
    """

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            await func(*args, **kwargs)
        except asyncio.CancelledError:
            pass
    return wrapper


def _get_connector() -> aiohttp.TCPConnector:
    """Return a TCPConnector with default ssl context.

    Returns
    -------
    aiohttp.TCPConnector
        Instance with default ssl connector.
    """
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    return aiohttp.TCPConnector(ssl=ssl_context)


def _get_current_version() -> str:
    """Return the version of running Wazuh instance.

    Returns
    -------
    str
        Wazuh version in X.Y.Z format.
    """
    return wazuh.__version__


def _is_running_in_master_node() -> bool:
    """Determine if cluster is disabled or API is running in a master node.

    Returns
    -------
    bool
        True if API is running in master node or if cluster is disabled else False.
    """
    cluster_config = read_cluster_config()

    return cluster_config['disabled'] or cluster_config['node_type'] == 'master'


def _update_check_is_enabled() -> bool:
    """Read the ossec.conf and check UPDATE_CHECK_OSSEC_FIELD value.

    Returns
    -------
    bool
        True if UPDATE_CHECK_OSSEC_FIELD is 'yes' or isn't present, else False.
    """
    global_configurations = get_ossec_conf(section='global')

    return global_configurations.get(UPDATE_CHECK_OSSEC_FIELD, 'yes') == 'yes'


async def modify_response_headers(request, response):
    # Delete 'Server' entry
    response.headers.pop('Server', None)


@cancel_signal_handler
async def check_installation_uid(app: web.Application) -> None:
    """Check if the installation UID exists, populate it if not and inject it into the application context.

    Parameters
    ----------
    app : web.Application
        Application context to inject the installation UID
    """
    if os.path.exists(INSTALLATION_UID_PATH):
        logger.info("Getting installation UID...")
        with open(INSTALLATION_UID_PATH, 'r') as file:
            installation_uid = file.readline()
    else:
        logger.info("Populating installation UID...")
        installation_uid = str(uuid.uuid4())
        with open(INSTALLATION_UID_PATH, 'w') as file:
            file.write(installation_uid)
            os.chown(file.name, common.wazuh_uid(), common.wazuh_gid())
            os.chmod(file.name, 0o660)
    app[INSTALLATION_UID_KEY] = installation_uid


@cancel_signal_handler
async def get_update_information(app: web.Application) -> None:
    """Get updates information from Update Check Service and inject into the application context.

    Parameters
    ----------
    app : web.Application
        Application context to inject the update information.
    """

    while True:
        logger.info('Getting updates information...')
        app[UPDATE_INFORMATION_KEY] = await query_update_check_service(app[INSTALLATION_UID_KEY])

        await asyncio.sleep(ONE_DAY_SLEEP)


async def register_background_tasks(app: web.Application) -> AsyncGenerator:
    """Cleanup context to handle background tasks.

    Parameters
    ----------
    app : web.Application
        Application context to pass to tasks.
    """
    tasks: list[asyncio.Task] = []

    if _is_running_in_master_node() and _update_check_is_enabled():
        tasks.append(asyncio.create_task(check_installation_uid(app)))
        tasks.append(asyncio.create_task(get_update_information(app)))

    yield

    for task in tasks:
        task.cancel()
        await task
