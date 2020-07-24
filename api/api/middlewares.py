# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from base64 import b64decode
from json import loads
from logging import getLogger
from time import time
from connexion.problem import problem as connexion_problem
from connexion.exceptions import ProblemException, ExtraParameterProblem

from aiohttp import web

from api import configuration
from api.util import raise_if_exc
from wazuh.core.exception import WazuhError

logger = getLogger('wazuh')


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response


ip_stats = dict()
ip_block = set()


@web.middleware
async def prevent_bruteforce_attack(request, handler):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly"""
    global ip_stats, ip_block
    if 'authenticate' in request.path:
        try:
            if time() - configuration.security_conf['block_time'] >= ip_stats[request.remote]['timestamp']:
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

        if ip_stats[request.remote]['attempts'] >= configuration.security_conf['max_login_attempts']:
            ip_block.add(request.remote)

    response = await handler(request)

    return response


@web.middleware
async def response_postprocessing(request, handler):
    """Remove unwanted fields from error responses like 400 or 403.

    Additionally, it cleans the output given by connexion's exceptions. If no exception is raised during the
    'await handler(request) it means the output will be a 200 response and no fields needs to be removed."""
    fields_to_remove = ['status']

    def cleanup_str(detail):
        return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())

    try:
        return await handler(request)
    except ProblemException as ex:
        if isinstance(ex, ExtraParameterProblem):
            del ex.__dict__['extra_formdata']
            del ex.__dict__['extra_query']
            ex.__dict__['type'] = 'about:blank'
            ex.__dict__['title'] = 'Bad Request'

        problem = connexion_problem(**ex.__dict__)
        for field in fields_to_remove:
            if field in problem.body:
                del problem.body[field]
        problem.body['detail'] = cleanup_str(problem.body['detail'])
        return problem


request_counter = 0
current_time = None


@web.middleware
async def prevent_denial_of_service(request, handler):
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
