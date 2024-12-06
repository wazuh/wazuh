# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.lifecycle import ConnexionRequest, ConnexionResponse
from connexion import exceptions

from content_size_limit_asgi.errors import ContentSizeExceeded

from server_management_api.middlewares import ip_block, ip_stats, LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT
from server_management_api.api_exception import ExpectFailedException
from server_management_api.controllers.util import json_response, ERROR_CONTENT_TYPE
from wazuh.core.utils import get_utc_now
from wazuh.core.config.client import CentralizedConfig


def prevent_bruteforce_attack(request: ConnexionRequest, attempts: int = 5):
    """Check that the IPs that are requesting an API token do not do so repeatedly.

    Parameters
    ----------
    request : ConnexionRequest
        HTTP request.
    attempts : int
        Number of attempts until an IP is blocked.
    """

    if request.scope['path'] in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and \
            request.method in {'GET', 'POST'}:
        if request.client.host not in ip_stats:
            ip_stats[request.client.host] = dict()
            ip_stats[request.client.host]['attempts'] = 1
            ip_stats[request.client.host]['timestamp'] = get_utc_now().timestamp()
        else:
            ip_stats[request.client.host]['attempts'] += 1

        if ip_stats[request.client.host]['attempts'] >= attempts:
            ip_block.add(request.client.host)


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


async def expect_failed_error_handler(request: ConnexionRequest, exc: ExpectFailedException) -> ConnexionResponse:
    """Handler for the 'Expect' HTTP header.

    Parameters
    ----------
    request : ConnexionRequest
        Incoming request.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Expectation failed",
    }
    if exc.detail:
        problem['detail'] = exc.detail

    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=exc.status, content_type=ERROR_CONTENT_TYPE)


async def unauthorized_error_handler(request: ConnexionRequest,
                                     exc: exceptions.Unauthorized) -> ConnexionResponse:
    """Unauthorized Exception Error handler.

    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc : Unauthorized
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Unauthorized",
    }
    if request.scope['path'] in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and \
        request.method in {'GET', 'POST'}:
        problem["detail"] = "Invalid credentials"

        prevent_bruteforce_attack(
            request=request,
            attempts=CentralizedConfig.get_management_api_config().access.max_login_attempts
        )
    else:
        problem.update({'detail': exc.detail} \
                            if 'token_info' not in request.context \
                            else {})
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=exc.status_code, content_type=ERROR_CONTENT_TYPE)


async def http_error_handler(request: ConnexionRequest,
                             exc: exceptions.HTTPException) -> ConnexionResponse:
    """HTTPError Exception Error handler.

    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc : HTTPException
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """

    problem = {
        'title': exc.detail,
        "detail": f"{exc.status_code}: {exc.detail}",
    }
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=exc.status_code, content_type=ERROR_CONTENT_TYPE)


async def problem_error_handler(request: ConnexionRequest, exc: exceptions.ProblemException) -> ConnexionResponse:
    """ProblemException Error handler.

    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc : ProblemException
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": exc.title if exc.title else 'Bad Request',
        "detail": exc.detail if isinstance(exc.detail, dict) else _cleanup_detail_field(exc.detail)
    }
    problem.update({"type": exc.type} if (exc.type and exc.type != 'about:blank') else {})
    problem.update(exc.ext if exc.ext else {})
    if isinstance(problem['detail'], dict):
        for field in ['status', 'type']:
            if field in problem['detail']:
                problem['detail'].pop(field)
    if 'code' in problem:
        problem['error'] = problem.pop('code')
    if not problem['detail']:
        del problem['detail']

    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=exc.__dict__['status'], content_type=ERROR_CONTENT_TYPE)


async def content_size_handler(request: ConnexionRequest, exc: ContentSizeExceeded) -> ConnexionResponse:
    """Content size error handler.

    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc : ContentSizeExceeded
        Raised exception.

    Returns
    -------
    Response
        Returns status code 413 if the maximum upload file size is exceeded.
    """
    problem = {
        "title": "Content size exceeded.",
        "detail": str(exc)
    }
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=413, content_type=ERROR_CONTENT_TYPE)
