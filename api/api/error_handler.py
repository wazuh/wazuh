# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion.lifecycle import ConnexionRequest, ConnexionResponse
from connexion import exceptions
from connexion.security import AbstractSecurityHandler

from content_size_limit_asgi.errors import ContentSizeExceeded

from api import configuration
from api.authentication import decode_token
from api.middlewares import LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT, charge_unauthenticated_request
from api.api_exception import ExpectFailedException, MaxRequestsException
from api.controllers.util import json_response, build_recursion_error_response, ERROR_CONTENT_TYPE

logger = logging.getLogger('wazuh-api')


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
    else:
        problem.update({'detail': exc.detail} \
                            if 'token_info' not in request.context \
                            else {})
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=exc.status_code, content_type=ERROR_CONTENT_TYPE)


async def http_error_handler(request: ConnexionRequest,
                             exc: exceptions.HTTPException) -> ConnexionResponse:
    """HTTPError Exception Error handler.

    A 404 or 405 is answered with a 401 unless the request carries a valid bearer token, so that an
    unauthenticated caller cannot tell which routes and methods exist. One that no rate-limit
    middleware charged is charged here against the unauthenticated bucket.

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

    status_code = exc.status_code
    problem = {
        'title': exc.detail,
        "detail": f"{exc.status_code}: {exc.detail}",
    }
    # connexion applies the security requirement only to a request that matched an operation, so
    # these two never went through authentication. The 401 is built here, not by
    # `unauthorized_error_handler`, which words it "Invalid credentials" on the login paths.
    if status_code in {404, 405}:
        # connexion's router raises a 405 above every rate-limit middleware, and a 404 is charged by
        # CheckAuthenticatedRateLimitMiddleware only when max_request_per_minute registers it. The
        # charge comes first so that `decode_token` below is bounded for a valid token as well.
        access = configuration.api_conf['access']
        if (status_code == 405 or not access['max_request_per_minute']) and await charge_unauthenticated_request(
                request, access['max_unauthenticated_request_per_minute'], 6005):
            return await problem_error_handler(request, MaxRequestsException(code=6005))
        try:
            auth_type, token = AbstractSecurityHandler.get_auth_header_value(request)
            if auth_type != 'bearer':
                raise exceptions.Unauthorized("No authorization token provided")
            await decode_token(token)
        except exceptions.Unauthorized as unauthorized:
            status_code = unauthorized.status_code
            problem = {"title": "Unauthorized", "detail": unauthorized.detail}
        except Exception as error:
            # An exception raised in here is not dispatched again, so it would reach ServerErrorMiddleware
            # as an empty 500. A declared route answers the same failure with this JSON one.
            logger.error(f"Could not validate the token of a {status_code} response: {error!r}")
            if not isinstance(error, exceptions.ProblemException):
                error = exceptions.InternalServerError()
            return await problem_error_handler(request, error)
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=status_code, content_type=ERROR_CONTENT_TYPE)


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
    # The access log records this request like any other, so without a line naming the limit an
    # operator sees a bare 413 and no way to tell which setting refused it.
    logger.warning(f"Rejected a request to {request.scope.get('path', '')}: {exc}")

    # Same body as the ceiling `CheckExpectHeaderMiddleware` answers with, so a caller sees one
    # shape for 413 whether the limit was crossed at the header or while the body was being read.
    # It is also the shape `RequestTooLargeResponse` publishes in spec.yaml.
    problem = {
        "title": "Request Entity Too Large",
        "detail": str(exc),
        "error": 413
    }
    return json_response(data=problem, pretty=request.query_params.get('pretty', 'false') == 'true',
                         status_code=413, content_type=ERROR_CONTENT_TYPE)


async def recursion_error_handler(request: ConnexionRequest, exc: RecursionError) -> ConnexionResponse:
    """ Recursion error handler.
    
    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc : RecursionError
        Raised exception.

    Returns
    -------
    Response
        Returns status code 400 if the maximum recursion depth is exceeded,
            which can be caused by a too deeply nested JSON in the request body.
    """

    return build_recursion_error_response(
        pretty=request.query_params.get('pretty', 'false') == 'true'
    )
