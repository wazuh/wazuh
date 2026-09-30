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

from typing import Optional

from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from connexion.exceptions import OAuthProblem
from connexion.lifecycle import ConnexionRequest
from connexion.security import AbstractSecurityHandler

from secure import Secure, ContentSecurityPolicy, XFrameOptions, Server

from wazuh.core.utils import get_utc_now

from api import configuration
from api.alogging import MAX_LOGGED_BODY_SIZE, custom_logging
from api.authentication import generate_keypair, JWT_ALGORITHM
from api.api_exception import BlockedIPException, MaxRequestsException, ExpectFailedException
from api.configuration import default_api_configuration

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
start_stop_logger = logging.getLogger('start-stop-api')

ip_stats = dict()
ip_block = set()
general_request_counter = 0
general_current_time = None
events_request_counter = 0
events_current_time = None


def get_declared_content_length(request: Request) -> Optional[int]:
    """Get the body size the request declares in its `Content-Length` header.

    The header is readable before a single byte of the body is consumed, and the ASGI server never
    delivers more body than the request declares, so it is a sound upper bound on what reading the
    body would cost -- except when the request also carries `Transfer-Encoding`, in which case the
    server frames the body by chunks and `Content-Length` bounds nothing.

    Parameters
    ----------
    request : Request
        HTTP request.

    Returns
    -------
    Optional[int]
        Declared body length, or None when the header is absent, malformed, negative, or the
        request is chunked.
    """
    if 'transfer-encoding' in request.headers:
        return None

    try:
        declared_length = int(request.headers.get('content-length'))
    except (TypeError, ValueError):
        return None

    # A negative length is not a length at all: treating it as unknown sends the request down the
    # same path as a chunked one instead of letting it slip past an upper-bound comparison it
    # cannot fail.
    return declared_length if declared_length >= 0 else None


async def access_log(request: ConnexionRequest, response: Response, prev_time: time):
    """Generate Log message from the request."""

    time_diff = time.time() - prev_time

    context = request.context if hasattr(request, 'context') else {}
    headers = request.headers if hasattr(request, 'headers') else {}
    path = request.scope.get('path', '') if hasattr(request, 'scope') else ''
    host = request.client.host if hasattr(request, 'client') else ''
    method = request.method if hasattr(request, 'method') else ''
    query = dict(request.query_params) if hasattr(request, 'query_params') else {}
    hash_auth_context = context.get('token_info', {}).get(HASH_AUTH_CONTEXT_KEY, '')

    # Only a caller the security handler accepted gets its payload recorded. connexion writes the
    # identity into the request context once, and only once, authentication has succeeded, so its
    # presence is the answer -- not the response status, which cannot distinguish a rejection issued
    # above the security handler from the same code returned to an authenticated caller further down.
    log_body = bool(context.get('user', None) or context.get('token_info', None))

    # The body is deserialised here, after the response, and no longer in the middleware before the
    # request was dispatched: nothing should build an object graph out of a payload for a caller
    # nobody has authenticated yet. It is parsed only where the result is used -- written to the
    # logs, or hashed into a run_as auth context identifier -- and only from bytes the middleware
    # already cached, never by reading the stream again. `RecursionError` degrades to an empty body
    # rather than raising, since this runs after the response has already been sent; a payload that
    # parses to something other than a mapping (None, a list, a scalar) is kept as-is instead, since
    # only a mapping can be masked.
    body_read = hasattr(request, '_body')
    body = {}
    if body_read and (log_body or path == RUN_AS_LOGIN_ENDPOINT):
        try:
            body = await request.json()
        except RecursionError:
            body = {}

    if 'password' in query:
        query['password'] = '****'
    # `body` is whatever `request.json()` returned, which is None for a malformed, null or binary
    # payload and a non-dict for a JSON list or scalar. Only a mapping can carry these fields, and
    # only a mapping supports the assignment; guard so a small unparsable body from an authenticated
    # caller degrades to an unmasked log line rather than a 500 raised after the response was sent.
    if isinstance(body, dict):
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
                s = jwt.decode(user_passw, generate_keypair()[1],
                            algorithms=[JWT_ALGORITHM],
                            audience='Wazuh API REST',
                            options={'verify_exp': False})
                user = s['sub']
                if HASH_AUTH_CONTEXT_KEY in s:
                    hash_auth_context = s[HASH_AUTH_CONTEXT_KEY]
        except (KeyError, IndexError, binascii.Error, jwt.exceptions.PyJWTError, OAuthProblem):
            user = UNKNOWN_USER_STRING

    # Create hash if run_as login. Only from a body that was actually read: hashing the empty
    # placeholder that stands in for a payload nothing cached would stamp every such attempt with
    # the same constant digest instead of leaving the field empty.
    if not hash_auth_context and path == RUN_AS_LOGIN_ENDPOINT and body_read:
        hash_auth_context = hashlib.blake2b(json.dumps(body).encode(),
                                            digest_size=16).hexdigest()

    # The auth context hash computed above is kept even when the body is not logged: it is a
    # fixed-size digest, and it is precisely the useful field for a run_as attempt that failed.
    if not log_body:
        body = {}

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
    access_conf = configuration.api_conf['access']
    block_time = access_conf['block_time']
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
        max_request_per_minute = configuration.api_conf['access']['max_request_per_minute']
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

        # connexion passes a shallow copy of the scope downwards; creating `extensions` here makes
        # the copy share it, so the identity the security handler writes into it is visible to
        # access_log through `request.context`.
        request.scope.setdefault('extensions', {})

        # This is the outermost middleware, so reading every body here handed an unauthenticated
        # caller a max_upload_size buffer, once per request, before the security handler had been
        # asked who was calling. Only the bytes are buffered, and only when they are small enough to
        # be worth logging -- access_log runs after the response, when the stream is gone, so they
        # have to be cached here for it to report them; deserialising them is deferred to access_log,
        # which by then knows whether the result is needed at all. Reading is bounded by the declared
        # length, since the ASGI server never delivers more body than the request declares; a
        # request that declares none, or declares more than is worth logging, is left for the
        # endpoint to read and its body does not reach the log.
        content_length = get_declared_content_length(request)
        if content_length is not None and 0 < content_length <= MAX_LOGGED_BODY_SIZE:
            # Related to https://github.com/wazuh/wazuh/issues/24060.
            await request.body()

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
    