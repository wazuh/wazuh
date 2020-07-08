# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from base64 import b64decode
from json import loads
from logging import getLogger
from time import time

from aiohttp import web

from api import configuration
from api.api_exception import APIError
from api.util import raise_if_exc
from wazuh.core.exception import WazuhError

logger = getLogger('wazuh')


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response


@web.middleware
async def check_experimental(request, handler):
    if 'experimental' in request.path:
        if not configuration.api_conf['experimental_features']:
            raise_if_exc(APIError(code=2008))

    response = await handler(request)
    return response


ip_stats = dict()
ip_block = set()


@web.middleware
async def prevent_bruteforce_attack(request, handler):
    global ip_stats, ip_block
    if 'authenticate' in request.path:
        try:
            if time() - configuration.security_conf['block_time'] >= ip_stats[request.remote]['timestamp']:
                ip_stats.pop(request.remote)
                ip_block.remove(request.remote)
        except (KeyError, ValueError):
            pass

        if request.remote in ip_block:
            logger.warning(f'IP blocked due to number of failed logins: {request.remote}')
            raise_if_exc(WazuhError(6000))

        if request.remote not in ip_stats.keys():
            ip_stats[request.remote] = dict()
            ip_stats[request.remote]['attempts'] = 1
            ip_stats[request.remote]['timestamp'] = time()
        else:
            ip_stats[request.remote]['attempts'] += 1

        if ip_stats[request.remote]['attempts'] >= configuration.security_conf['max_login_attempts']:
            ip_block.add(request.remote)

    response = await handler(request)

    return response


request_counter = 0
current_time = None


@web.middleware
async def prevent_denial_of_service(request, handler):
    if 'authenticate' not in request.path:
        global current_time, request_counter
        if not current_time:
            current_time = time()

        if time() - 60 <= current_time:
            request_counter += 1
        else:
            request_counter = 0
            current_time = time()

        if request_counter > configuration.security_conf['max_request_per_minute']:
            logger.debug(f'Request rejected due to high request per minute: Source IP: {request.remote}')
            try:
                payload = dict(request.raw_headers)[b'Authorization'].decode().split('.')[1]
            except KeyError:
                payload = dict(request.raw_headers)[b'authorization'].decode().split('.')[1]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            request['user'] = loads(b64decode(payload).decode())['sub']
            raise_if_exc(WazuhError(6001), code=429)
    response = await handler(request)

    return response
