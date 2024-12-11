# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import binascii
import json
import hashlib
import time
import logging
import base64
import jwt

from connexion.exceptions import OAuthProblem
from connexion.lifecycle import ConnexionRequest
from connexion.security import AbstractSecurityHandler
from secure import Secure, ContentSecurityPolicy, XFrameOptions, Server
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from wazuh.core.utils import get_utc_now

from api.alogging import custom_logging
from api.api_exception import BlockedIPException, MaxRequestsException, ExpectFailedException
from api.configuration import default_api_configuration
from wazuh.core.authentication import get_keypair, JWT_ALGORITHM
from wazuh.core.config.client import CentralizedConfig

# Default of the max event requests allowed per minute
MAX_REQUESTS_EVENTS_DEFAULT = 30

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"
LOGIN_ENDPOINT = '/security/user/authenticate'

# Authentication context hash key
HASH_AUTH_CONTEXT_KEY = 'hash_auth_context'

# API secure headers
server = Server().set("Wazuh")
csp = ContentSecurityPolicy().set('none')
xfo = XFrameOptions().deny()
secure_headers = Secure(server=server, csp=csp, xfo=xfo)

logger = logging.getLogger('wazuh-api')

ip_stats = dict()
ip_block = set()
general_request_counter = 0
general_current_time = None
events_request_counter = 0
events_current_time = None


async def access_log(request: ConnexionRequest, response: Response, prev_time: time):
    """Generate Log message from the request."""

    time_diff = time.time() - prev_time

    context = request.context if hasattr(request, 'context') else {}
    headers = request.headers if hasattr(request, 'headers') else {}
    path = request.scope.get('path', '') if hasattr(request, 'scope') else ''
    host = request.client.host if hasattr(request, 'client') else ''
    method = request.method if hasattr(request, 'method') else ''
    query = dict(request.query_params) if hasattr(request, 'query_params') else {}
    # If the request content is valid, the _json attribute is set when the
    # first time the json function is awaited. This check avoids raising an
    # exception when the request json content is invalid.
    body = await request.json() if hasattr(request, '_json') else {}
    hash_auth_context = context.get('token_info', {}).get(HASH_AUTH_CONTEXT_KEY, '')

    if 'password' in query:
        query['password'] = '****'
    if 'password' in body:
        body['password'] = '****'
    if 'key' in body and '/agents' in path:
        body['key'] = '****'

    # Get the username from the request. If it is not found in the context, try
    # to get it from the headers using basic or bearer authentication methods.
    if not (user := context.get('user', None)):
        try:
            auth_type, user_passw = AbstractSecurityHandler.get_auth_header_value(request)
            if auth_type == 'basic':
                user, _ = base64.b64decode(user_passw).decode("latin1").split(":", 1)
            elif auth_type == 'bearer':
                _, public_key = get_keypair()
                s = jwt.decode(user_passw, public_key,
                            algorithms=[JWT_ALGORITHM],
                            audience='Wazuh API REST',
                            options={'verify_exp': False})
                user = s['sub']
                if HASH_AUTH_CONTEXT_KEY in s:
                    hash_auth_context = s[HASH_AUTH_CONTEXT_KEY]
        except (KeyError, IndexError, binascii.Error, jwt.exceptions.PyJWTError, OAuthProblem):
            user = UNKNOWN_USER_STRING

    # Create hash if run_as login
    if not hash_auth_context and path == RUN_AS_LOGIN_ENDPOINT:
        hash_auth_context = hashlib.blake2b(json.dumps(body).encode(),
                                            digest_size=16).hexdigest()

    custom_logging(user, host, method, path, query, body, time_diff, response.status_code,
                   hash_auth_context=hash_auth_context, headers=headers)
    if response.status_code == 403 and \
        path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and \
            method in {'GET', 'POST'}:
        logger.warning(f'IP blocked due to exceeded number of logins attempts: {host}')


def check_blocked_ip(request: Request):
    """Blocks/unblocks the IPs that are requesting an API token.

    Parameters
    ----------
    request : Request
        HTTP request.
    block_time : int
        Block time used to decide if the IP is going to be unlocked.

    """
    global ip_block, ip_stats
    access_conf = CentralizedConfig.get_management_api_config().access
    block_time = access_conf.block_time
    try:
        if get_utc_now().timestamp() - block_time >= ip_stats[request.client.host]['timestamp']:
            del ip_stats[request.client.host]
            ip_block.remove(request.client.host)
    except (KeyError, ValueError):
        pass
    if request.client.host in ip_block:
        raise BlockedIPException(
            status=403,
            title="Permission Denied",
            detail="Limit of login attempts reached. The current IP has been blocked due "
                    "to a high number of login attempts")


def check_rate_limit(
    request_counter_key: str,
    current_time_key: str,
    max_requests: int,
    error_code: int
) -> int:
    """Check that the maximum number of requests per minute
    passed in `max_requests` is not exceeded.

    Parameters
    ----------
    request_counter_key : str
        Key of the request counter variable to get from globals() dict.
    current_time_key : str
        Key of the current time variable to get from globals() dict.
    max_requests : int
        Maximum number of requests per minute permitted.
    error_code : int
        error code to return if the counter is greater than max_requests.

    Return
    ------
        0 if the counter is greater than max_requests
        else error_code.
    """
    if not globals()[current_time_key]:
        globals()[current_time_key] = get_utc_now().timestamp()

    if get_utc_now().timestamp() - 60 <= globals()[current_time_key]:
        globals()[request_counter_key] += 1
    else:
        globals()[request_counter_key] = 0
        globals()[current_time_key] = get_utc_now().timestamp()

    if globals()[request_counter_key] > max_requests:
        return error_code

    return 0


class CheckRateLimitsMiddleware(BaseHTTPMiddleware):
    """Rate Limits Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """"Check request limits per minute."""
        max_request_per_minute = CentralizedConfig.get_management_api_config().access.max_request_per_minute
        error_code = check_rate_limit(
            'general_request_counter',
            'general_current_time',
            max_request_per_minute,
            6001)

        if request.url.path == '/events':
            error_code = check_rate_limit(
                'events_request_counter',
                'events_current_time',
                MAX_REQUESTS_EVENTS_DEFAULT,
                6005)

        if error_code:
            raise MaxRequestsException(code=error_code)
        else:
            return await call_next(request)


class CheckBlockedIP(BaseHTTPMiddleware):
    """Rate Limits Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """"Update and check if the client IP is locked."""
        if request.url.path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} \
           and request.method in {'GET', 'POST'}:
            check_blocked_ip(request)
        return await call_next(request)


class WazuhAccessLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware to log custom Access messages."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Log Wazuh access information.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        prev_time = time.time()

        body = await request.body()
        if body:
            try:
                # Load the request body to the _json field before calling the controller so it's cached before the stream 
                # is consumed. If there's a json error we skip it so it's handled later.
                # Related to https://github.com/wazuh/wazuh/issues/24060.
                _ = await request.json()
            except json.decoder.JSONDecodeError:
                pass

        response = await call_next(request)
        await access_log(ConnexionRequest.from_starlette_request(request), response, prev_time)
        return response


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Secure headers Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Check and modifies the response headers with secure package.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        resp = await call_next(request)
        secure_headers.framework.starlette(resp)
        return resp

class CheckExpectHeaderMiddleware(BaseHTTPMiddleware):
    """Middleware to check for the 'Expect' header in incoming requests."""

    async def dispatch(self, request: ConnexionRequest, call_next: RequestResponseEndpoint) -> Response:
        """Check for specific request headers and generate error 417 if conditions are not met.
                
        Parameters
        ----------
            request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.
        
        Returns
        -------
            Returned response.
        """
        
        if 'Expect' not in request.headers:
            response = await call_next(request)
            return response
        else:
            expect_value = request.headers["Expect"].lower()
            
            if expect_value != '100-continue':
                raise ExpectFailedException(status=417, title="Expectation failed", detail="Unknown Expect")
            
            if 'Content-Length' in request.headers:
                content_length = int(request.headers["Content-Length"])
                max_upload_size = default_api_configuration["max_upload_size"]
                if content_length > max_upload_size:
                    raise ExpectFailedException(status=417, title="Expectation failed",
                                                detail=f"Maximum content size limit ({max_upload_size}) exceeded "
                                                       f"({content_length} bytes read)")
                
        response = await call_next(request)
        return response
    