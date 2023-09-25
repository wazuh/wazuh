# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import os
import ssl
import uuid
from datetime import datetime

import aiohttp
import certifi
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.security import load_spec

from api.configuration import api_conf
from api.constants import INSTALLATION_UID_PATH

RELEASE_UPDATES_URL = 'http://cti:4041'

logger = logging.getLogger('wazuh-api')


def cancel_signal_handler(func):
    async def wrapper(*args, **kwargs):
        try:
            await func(*args, **kwargs)
        except asyncio.CancelledError:
            pass
    return wrapper


def get_connector():
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    return aiohttp.TCPConnector(ssl=ssl_context)


def get_current_version():
    spec = load_spec()
    return spec['info']['version']


def get_installation_uid():
    with open(INSTALLATION_UID_PATH, 'r') as file:
        return file.readline()


def is_running_in_master_node() -> bool:
    cluster_config = read_cluster_config()

    return cluster_config['disabled'] or cluster_config['node_type'] == 'master'


async def modify_response_headers(request, response):
    # Delete 'Server' entry
    response.headers.pop('Server', None)


@cancel_signal_handler
async def check_installation_uid(app):
    if not os.path.exists(INSTALLATION_UID_PATH):
        logger.info("Populating installation UID...")
        with open(INSTALLATION_UID_PATH, 'w') as file:
            file.write(str(uuid.uuid4()))


@cancel_signal_handler
async def get_update_information(app):
    # Validate if api is on master node or not

    headers = {
        'wazuh-uid': get_installation_uid(),
        'wazuh-tag': f'v{get_current_version()}'
    }

    updates_url = os.path.join(RELEASE_UPDATES_URL, 'api', 'v1', 'ping')

    async with aiohttp.ClientSession(connector=get_connector()) as session:
        while True:
            logger.info('Getting updates information...')
            logger.debug('Querying %s', updates_url)
            async with session.get(updates_url, headers=headers) as response:
                response_data = await response.json()

                logger.debug("Response status %s", response.status)
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
            await asyncio.sleep(60*60*24)


async def register_background_tasks(app):
    tasks: list[asyncio.Task] = []

    if is_running_in_master_node():
        tasks.append(asyncio.create_task(check_installation_uid(app)))
        tasks.append(asyncio.create_task(get_update_information(app)))

    yield

    for task in tasks:
        task.cancel()
        await task
