# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import ssl
import uuid
from datetime import datetime
from functools import wraps
from typing import AsyncGenerator, Callable

import aiohttp
import certifi
from aiohttp import web
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.security import load_spec

from api.constants import INSTALLATION_UID_PATH

RELEASE_UPDATES_URL = 'http://cti:4041'
ONE_DAY_SLEEP = 60*60*24
INSTALLATION_UID_KEY = 'installation_uid'

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
    """Return the version of running Wazuh instance

    Returns
    -------
    str
        Wazuh version in format X.Y.Z format.
    """
    spec = load_spec()
    return spec['info']['version']


def _is_running_in_master_node() -> bool:
    """Determine if cluster is disabled or API is running in a master node.

    Returns
    -------
    bool
        True if API is runing in master node or if cluster is disabled else False.
    """
    cluster_config = read_cluster_config()

    return cluster_config['disabled'] or cluster_config['node_type'] == 'master'


async def modify_response_headers(request, response):
    # Delete 'Server' entry
    response.headers.pop('Server', None)


@cancel_signal_handler
async def check_installation_uid(app: web.Application) -> None:
    """Check if the installation UID, populate if not and inject into the application context.

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
    app[INSTALLATION_UID_KEY] = installation_uid


@cancel_signal_handler
async def get_update_information(app: web.Application) -> None:
    """Get updates information from Update Check Service and inject into the application context.

    Parameters
    ----------
    app : web.Application
        Application context to inject the update information
    """
    headers = {
        'wazuh-uid': app[INSTALLATION_UID_KEY],
        'wazuh-tag': f'v{_get_current_version()}'
    }

    updates_url = os.path.join(RELEASE_UPDATES_URL, 'api', 'v1', 'ping')

    async with aiohttp.ClientSession(connector=_get_connector()) as session:
        while True:
            logger.info('Getting updates information...')
            logger.debug('Querying %s', updates_url)
            try:
                async with session.get(updates_url, headers=headers) as response:
                    response_data = await response.json()

                    logger.debug("Response status: %s", response.status)
                    logger.debug("Response data: %s", response_data)

                    update_information = {
                        'last_check_date': datetime.utcnow(),
                        'status_code': response.status,
                        'message': '',
                        'available_update': {}
                    }

                    if response.status == 200:
                        if len(response_data['data']['patch']):
                            update_information['available_update'].update(**response_data['data']['patch'][0])
                        elif len(response_data['data']['minor']):
                            update_information['available_update'].update(**response_data['data']['minor'][0])
                        elif len(response_data['data']['mayor']):
                            update_information['available_update'].update(**response_data['data']['mayor'][0])
                    else:
                        update_information['message'] = response_data['errors']['detail']

                    app['update_information'] = update_information
            except aiohttp.ClientError as err:
                logger.error("Something was wrong querying the update check service.", exc_info=err)
            except Exception as err:
                logger.error("An unknown error occurs trying to get updates information.", exc_info=err)
            finally:
                await asyncio.sleep(ONE_DAY_SLEEP)


async def register_background_tasks(app: web.Application) -> AsyncGenerator:
    """Cleanup context to handle background tasks.

    Parameters
    ----------
    app : web.Application
        Application context to pass to tasks.
    """
    tasks: list[asyncio.Task] = []

    if _is_running_in_master_node():
        tasks.append(asyncio.create_task(check_installation_uid(app)))
        tasks.append(asyncio.create_task(get_update_information(app)))

    yield

    for task in tasks:
        task.cancel()
        await task
