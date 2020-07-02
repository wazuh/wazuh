# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from time import time

from aiohttp import web

from api import configuration
from api.api_exception import APIError
from api.util import raise_if_exc
from wazuh.core.exception import WazuhError


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
block_time = 3600
n_attempts = 5


@web.middleware
async def prevent_denial_of_service(request, handler):
    if 'authenticate' in request.path:
        try:
            if time() - block_time >= ip_stats[request.remote]['timestamp']:
                ip_stats.pop(request.remote)
                ip_block.remove(request.remote)
        except (KeyError, ValueError):
            pass

        if request.remote in ip_block:
            raise_if_exc(WazuhError(6000))

        if request.remote not in ip_stats.keys():
            ip_stats[request.remote] = dict()
            ip_stats[request.remote]['attempts'] = 1
            ip_stats[request.remote]['timestamp'] = time()
        else:
            ip_stats[request.remote]['attempts'] += 1

        if ip_stats[request.remote]['attempts'] >= n_attempts:
            ip_block.add(request.remote)

    response = await handler(request)

    # If the user is correctly authenticate, his restrictions must be remove
    ip_stats.pop(request.remote)
    ip_block.remove(request.remote)

    return response
