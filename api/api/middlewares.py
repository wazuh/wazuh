# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import concurrent.futures
from json import JSONDecodeError

from logging import getLogger
from time import time

from aiohttp import web
from aiohttp.web_exceptions import HTTPException
from connexion.exceptions import ProblemException, OAuthProblem, Unauthorized
from connexion.problem import problem as connexion_problem

from api.configuration import api_conf
from api.util import raise_if_exc
from wazuh.core.exception import WazuhTooManyRequests, WazuhPermissionError

logger = getLogger('wazuh-api')
pool = concurrent.futures.ThreadPoolExecutor()


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    return await handler(request)


ip_stats = dict()
ip_block = set()
request_counter = 0
current_time = None


async def unlock_ip(request, block_time):
    """This function blocks/unblocks the IPs that are requesting an API token"""
    global ip_block, ip_stats
    try:
        if time() - block_time >= ip_stats[request.remote]['timestamp']:
            ip_stats.pop(request.remote)
            ip_block.remove(request.remote)
    except (KeyError, ValueError):
        pass

    if request.remote in ip_block:
        logger.warning(f'IP blocked due to exceeded number of logins attempts: {request.remote}')
        raise_if_exc(WazuhPermissionError(6000))


async def prevent_bruteforce_attack(request, attempts=5):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly"""
    global ip_stats, ip_block
    if request.path == '/security/user/authenticate' and request.method in ['GET', 'POST']:
        if request.remote not in ip_stats.keys():
            ip_stats[request.remote] = dict()
            ip_stats[request.remote]['attempts'] = 1
            ip_stats[request.remote]['timestamp'] = time()
        else:
            ip_stats[request.remote]['attempts'] += 1

        if ip_stats[request.remote]['attempts'] >= attempts:
            ip_block.add(request.remote)


@web.middleware
async def request_logging(request, handler):
    """Add request info to logging."""
    logger.debug2(f'Receiving headers {dict(request.headers)}')
    try:
        body = f' and body {await request.json()}'
    except JSONDecodeError:
        body = ''
    logger.debug(f'Receiving request "{request.method} {request.path}" with parameters {dict(request.query)}{body}')
    return await handler(request)


@web.middleware
async def prevent_denial_of_service(request, max_requests=300):
    """This function checks that the maximum number of requests per minute set in the configuration is not exceeded"""
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
        raise_if_exc(WazuhTooManyRequests(6001))


@web.middleware
async def security_middleware(request, handler):
    access_conf = api_conf['access']
    await prevent_denial_of_service(request, max_requests=access_conf['max_request_per_minute'])
    await unlock_ip(request=request, block_time=access_conf['block_time'])

    return await handler(request)


@web.middleware
async def response_postprocessing(request, handler):
    """Remove unwanted fields from error responses like 400 or 403.

    Additionally, it cleans the output given by connexion's exceptions. If no exception is raised during the
    'await handler(request) it means the output will be a 200 response and no fields needs to be removed."""

    def cleanup_detail_field(detail):
        return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())

    def remove_unwanted_fields(fields_to_remove=['status', 'type']):
        for field in fields_to_remove:
            if field in problem.body:
                del problem.body[field]
        if 'detail' in problem.body and problem.body['detail'] == '':
            del problem.body['detail']
        if 'code' in problem.body:
            problem.body['error'] = problem.body.pop('code')

    problem = None

    try:
        return await handler(request)

    except ProblemException as ex:
        problem = connexion_problem(ex.__dict__['status'],
                                    ex.__dict__['title'] if 'title' in ex.__dict__ and ex.__dict__['title'] else 'Bad Request',
                                    type=ex.__dict__['type'] if 'type' in ex.__dict__ else 'about:blank',
                                    detail=cleanup_detail_field(ex.__dict__['detail']) if 'detail' in ex.__dict__ else '',
                                    ext=ex.__dict__['ext'] if 'ext' in ex.__dict__ else None)
    except HTTPException as ex:
        problem = connexion_problem(ex.status,
                                    ex.reason if ex.reason else '',
                                    type=ex.reason if ex.reason else '',
                                    detail=ex.text if ex.text else '')
    except (OAuthProblem, Unauthorized):
        if request.path == '/security/user/authenticate' and request.method in ['GET', 'POST']:
            await prevent_bruteforce_attack(request=request, attempts=api_conf['access']['max_login_attempts'])
            problem = connexion_problem(401, "Unauthorized", type="about:blank", detail="Invalid credentials")
        else:
            problem = connexion_problem(401, "Unauthorized", type="about:blank",
                                        detail="No authorization token provided")
    finally:
        if problem:
            remove_unwanted_fields()
            return problem
