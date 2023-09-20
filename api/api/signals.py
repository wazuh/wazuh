# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
import ssl
import uuid

import aiohttp
import certifi

from wazuh.core.security import load_spec

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
    return str(uuid.uuid4())


async def modify_response_headers(request, response):
    # Delete 'Server' entry
    response.headers.pop('Server', None)


@cancel_signal_handler
async def get_update_information(app):
    # Validate if api is on master node or not

    headers = {
        'wazuh-uid': get_installation_uid(),
        'wazuh-tag': get_current_version()
    }

    async with aiohttp.ClientSession(connector=get_connector()) as session:
        while True:
            logger.info('Getting updates information')
            async with session.get('https://httpbin.org/get', headers=headers) as response:
                logger.debug("Response status %s", response.status)
                logger.debug("Response data: %s", await response.json())
            await asyncio.sleep(60*60*24)


async def start_background_tasks(app):
    app['get_update_information'] = asyncio.create_task(get_update_information(app))


async def cleanup_background_tasks(app):
    app['get_update_information'].cancel()
    await app['get_update_information']
