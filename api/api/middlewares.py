# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from json import JSONDecodeError
from logging import getLogger

from aiohttp import web, web_request
from aiohttp.web_exceptions import HTTPException
from connexion.exceptions import OAuthProblem, ProblemException, Unauthorized
from connexion.problem import problem as connexion_problem
from secure import SecureHeaders
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests
from wazuh.core.utils import get_utc_now

from api.configuration import api_conf
from api.util import raise_if_exc

MAX_REQUESTS_EVENTS_DEFAULT = 30

# API secure headers
secure_headers = SecureHeaders(server="Wazuh", csp="none", xfo="DENY")

logger = getLogger('wazuh-api')


def _cleanup_detail_field(detail: str) -> str:
    """Replace double endlines with '. ' and simple endlines with ''.

    Parameters
    ----------
    detail : str
        String to be modified.

    Returns
    -------
    str
        New value for the detail field.
    """
    return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())


@web.middleware
async def set_secure_headers(request, handler):
    resp = await handler(request)
    secure_headers.aiohttp(resp)
    return resp


ip_stats = dict()
ip_block = set()
general_request_counter = 0
general_current_time = None
events_request_counter = 0
events_current_time = None


async def unlock_ip(request: web_request.BaseRequest, block_time: int):
    """This function blocks/unblocks the IPs that are requesting an API token.

    Parameters
    ----------
    request : web_request.BaseRequest
        API request.
    block_time : int
        Block time used to decide if the IP is going to be unlocked.
    """
    global ip_block, ip_stats
    try:
        if get_utc_now().timestamp() - block_time >= ip_stats[request.remote]['timestamp']:
            del ip_stats[request.remote]
            ip_block.remove(request.remote)
    except (KeyError, ValueError):
        pass

    if request.remote in ip_block:
        logger.warning(f'IP blocked due to exceeded number of logins attempts: {request.remote}')
        raise_if_exc(WazuhPermissionError(6000))


async def prevent_bruteforce_attack(request: web_request.BaseRequest, attempts: int = 5):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly.

    Parameters
    ----------
    request : web_request.BaseRequest
        API request.
    attempts : int
        Number of attempts until an IP is blocked.
    """
    global ip_stats, ip_block
    if request.path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} and \
            request.method in {'GET', 'POST'}:
        if request.remote not in ip_stats.keys():
            ip_stats[request.remote] = dict()
            ip_stats[request.remote]['attempts'] = 1
            ip_stats[request.remote]['timestamp'] = get_utc_now().timestamp()
        else:
            ip_stats[request.remote]['attempts'] += 1

        if ip_stats[request.remote]['attempts'] >= attempts:
            ip_block.add(request.remote)


@web.middleware
async def request_logging(request, handler):
    """Add request info to logging."""
    logger.debug2(f'Receiving headers {dict(request.headers)}')
    try:
        body = await request.json()
        request['body'] = body
    except JSONDecodeError:
        pass

    return await handler(request)


@web.middleware
async def check_rate_limit(
    request: web_request.BaseRequest,
    request_counter_key: str,
    current_time_key: str,
    max_requests: int
) -> None:
    """This function checks that the maximum number of requests per minute passed in `max_requests` is not exceeded.

    Parameters
    ----------
    request : web_request.BaseRequest
        API request.
    request_counter_key : str
        Key of the request counter variable to get from globals() dict.
    current_time_key : str
        Key of the current time variable to get from globals() dict.
    max_requests : int, optional
        Maximum number of requests per minute permitted.
    """

    error_code_mapping = {
        'general_request_counter': {'code': 6001},
        'events_request_counter': {
            'code': 6005,
            'extra_message': f'For POST /events endpoint the limit is set to {max_requests} requests.'
        }
    }
    if not globals()[current_time_key]:
        globals()[current_time_key] = get_utc_now().timestamp()

    if get_utc_now().timestamp() - 60 <= globals()[current_time_key]:
        globals()[request_counter_key] += 1
    else:
        globals()[request_counter_key] = 0
        globals()[current_time_key] = get_utc_now().timestamp()

    if globals()[request_counter_key] > max_requests:
        logger.debug(f'Request rejected due to high request per minute: Source IP: {request.remote}')
        raise_if_exc(WazuhTooManyRequests(**error_code_mapping[request_counter_key]))


@web.middleware
async def security_middleware(request, handler):
    access_conf = api_conf['access']
    max_request_per_minute = access_conf['max_request_per_minute']

    if max_request_per_minute > 0:
        await check_rate_limit(
            request,
            'general_request_counter',
            'general_current_time',
            max_request_per_minute
        )

        if request.path == '/events':
            await check_rate_limit(
                request,
                'events_request_counter',
                'events_current_time',
                MAX_REQUESTS_EVENTS_DEFAULT
            )

    await unlock_ip(request, block_time=access_conf['block_time'])

    return await handler(request)


@web.middleware
async def response_postprocessing(request, handler):
    """Remove unwanted fields from error responses like 400 or 403.

    Additionally, it cleans the output given by connexion's exceptions. If no exception is raised during the
    'await handler(request) it means the output will be a 200 response and no fields needs to be removed.
    """

    def remove_unwanted_fields(fields_to_remove=None):
        fields_to_remove = fields_to_remove or ['status', 'type']
        for field in fields_to_remove:
            if field in problem.body:
                del problem.body[field]
        if problem.body.get('detail') == '':
            del problem.body['detail']
        if 'code' in problem.body:
            problem.body['error'] = problem.body.pop('code')

    problem = None

    try:
        return await handler(request)

    except ProblemException as ex:
        problem = connexion_problem(status=ex.__dict__['status'],
                                    title=ex.__dict__['title'] if ex.__dict__.get('title') else 'Bad Request',
                                    type=ex.__dict__.get('type', 'about:blank'),
                                    detail=_cleanup_detail_field(ex.__dict__['detail'])
                                    if 'detail' in ex.__dict__ else '',
                                    ext=ex.__dict__.get('ext'))
    except HTTPException as ex:
        problem = connexion_problem(ex.status,
                                    ex.reason if ex.reason else '',
                                    type=ex.reason if ex.reason else '',
                                    detail=ex.text if ex.text else '')
    except (OAuthProblem, Unauthorized) as auth_exception:
        if request.path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} and \
                request.method in {'GET', 'POST'}:
            await prevent_bruteforce_attack(request=request, attempts=api_conf['access']['max_login_attempts'])
            problem = connexion_problem(401, "Unauthorized", type="about:blank", detail="Invalid credentials")
        else:
            if isinstance(auth_exception, OAuthProblem):
                problem = connexion_problem(401, "Unauthorized", type="about:blank",
                                            detail="No authorization token provided")
            else:
                problem = connexion_problem(401, "Unauthorized", type="about:blank", detail="Invalid token")
    finally:
        problem and remove_unwanted_fields()

    return problem
