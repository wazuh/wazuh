# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import concurrent.futures
from base64 import b64decode
from json import loads
from logging import getLogger
from time import time

from aiohttp import web

from api.authentication import get_security_conf
from api.util import raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhError

logger = getLogger('wazuh')
pool = concurrent.futures.ThreadPoolExecutor()


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response


ip_stats = dict()
ip_block = set()
request_counter = 0
current_time = None


async def prevent_bruteforce_attack(request, block_time=300, attempts=5):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly"""
    global ip_stats, ip_block
    if 'authenticate' in request.path:
        try:
            if time() - block_time >= ip_stats[request.remote]['timestamp']:
                ip_stats.pop(request.remote)
                ip_block.remove(request.remote)
        except (KeyError, ValueError):
            pass

        if request.remote in ip_block:
            logger.warning(f'P blocked due to exceeded number of logins attempts: {request.remote}')
            raise_if_exc(WazuhError(6000))

        if request.remote not in ip_stats.keys():
            ip_stats[request.remote] = dict()
            ip_stats[request.remote]['attempts'] = 1
            ip_stats[request.remote]['timestamp'] = time()
        else:
            ip_stats[request.remote]['attempts'] += 1

        if ip_stats[request.remote]['attempts'] >= attempts:
            ip_block.add(request.remote)


async def prevent_denial_of_service(request, max_requests=300):
    """This function checks that the maximum number of requests per minute set in the configuration is not exceeded"""
    if 'authenticate' not in request.path:
        global current_time, request_counter
        if not current_time:
            current_time = time()

        if time() - 60 <= current_time:
            request_counter += 1
        else:
            request_counter = 0
            current_time = time()

        if request_counter > max_requests:
            logger.debug(f'Request rejected due to high request per minute: Source IP: {request.remote}')
            try:
                payload = dict(request.raw_headers)[b'Authorization'].decode().split('.')[1]
            except KeyError:
                payload = dict(request.raw_headers)[b'authorization'].decode().split('.')[1]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            request['user'] = loads(b64decode(payload).decode())['sub']
            raise_if_exc(WazuhError(6001), code=429)


@web.middleware
async def security_middleware(request, handler):
    dapi = DistributedAPI(f=get_security_conf,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=True,
                          logger=getLogger('wazuh')
                          )
    security_conf = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).dikt
    await prevent_bruteforce_attack(request, block_time=security_conf['block_time'],
                                    attempts=security_conf['max_login_attempts'])
    await prevent_denial_of_service(request, max_requests=security_conf['max_request_per_minute'])

    response = await handler(request)

    return response
