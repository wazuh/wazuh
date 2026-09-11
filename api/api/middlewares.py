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
import asyncio

from typing import Optional

from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from connexion.exceptions import OAuthProblem
from connexion.lifecycle import ConnexionRequest
from connexion.security import AbstractSecurityHandler

from secure import Secure, ContentSecurityPolicy, XFrameOptions, Server

from wazuh.core.exception import WazuhInternalError
from wazuh.core.utils import get_utc_now

from api import configuration
from api.alogging import MAX_LOGGED_BODY_SIZE, control_chars_pattern, custom_logging, escape_control_chars
from api.authentication import generate_keypair, JWT_ALGORITHM
from api.api_exception import BlockedIPException, ExpectFailedException, MaxRequestsException, PayloadTooLargeException

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"
LOGIN_ENDPOINT = '/security/user/authenticate'

# Authentication context hash key
HASH_AUTH_CONTEXT_KEY = 'hash_auth_context'

# Allowed upper bound for auth_context payload. Must not exceed MAX_LOGGED_BODY_SIZE: the access
# logger only caches a body up to that size, and a run_as attempt whose body was never cached is
# logged without its auth context hash.
AUTH_CONTEXT_MAX_PAYLOAD_SIZE = 8 * 1024

# Scope extensions key under which a middleware leaves a body it has already read, for the layers
# above it -- which never see the stream -- to report
CACHED_BODY_KEY = 'wazuh_cached_body'

# API secure headers
server = Server().set("Wazuh")
csp = ContentSecurityPolicy().set('none')
xfo = XFrameOptions().deny()
secure_headers = Secure(server=server, csp=csp, xfo=xfo)

logger = logging.getLogger('wazuh-api')
start_stop_logger = logging.getLogger('start-stop-api')

ip_stats = dict()
ip_block = set()
ip_lock = asyncio.Lock()
general_request_counter = 0
general_current_time = None


def get_declared_content_length(request: Request) -> Optional[int]:
    """Get the body size the request declares in its `Content-Length` header.

    The header is readable before a single byte of the body is consumed, and the ASGI server never
    delivers more body than the request declares, so it is a sound upper bound on what reading the
    body would cost. Requests that declare no length at all, i.e. chunked transfer encoding, have to
    be capped while they are read instead.

    Parameters
    ----------
    request : Request
        HTTP request.

    Returns
    -------
    Optional[int]
        Declared body length, or None when the header is absent, malformed or negative.
    """
    try:
        declared_length = int(request.headers.get('content-length'))
    except (TypeError, ValueError):
        return None

    # A negative length is not a length at all: treating it as unknown sends the request down the
    # capped-read path instead of letting it slip past an upper-bound comparison it cannot fail.
    return declared_length if declared_length >= 0 else None


async def read_capped_body(request: Request, limit: int, detail: str) -> bytes:
    """Read the request body, abandoning the stream as soon as `limit` bytes are exceeded.

    `Request.body()` materialises the whole payload and leaves the caller to measure it afterwards,
    so an oversized body has already been paid for by the time it is refused. This pulls the stream
    chunk by chunk and stops reading from the socket at the limit instead.

    A body that fits is cached in the request the same way `Request.body()` caches it, so it is
    still replayed to the middleware stack below. That cache is per `Request` object and travels
    downwards only, so a caller that also needs the bytes read here to be visible to an outer
    middleware has to publish them with `set_cached_body`.

    Parameters
    ----------
    request : Request
        HTTP request.
    limit : int
        Maximum body size allowed, in bytes.
    detail : str
        Detail reported in the exception when the body is too large.

    Returns
    -------
    bytes
        Request body.

    Raises
    ------
    PayloadTooLargeException
        If the body exceeds `limit` bytes.
    """
    if not hasattr(request, '_body'):
        chunks = []
        read = 0
        async for chunk in request.stream():
            read += len(chunk)
            if read > limit:
                raise PayloadTooLargeException(title="Request Entity Too Large", detail=detail)
            chunks.append(chunk)
        request._body = b''.join(chunks)

    if len(request._body) > limit:
        raise PayloadTooLargeException(title="Request Entity Too Large", detail=detail)

    return request._body


def set_cached_body(request: Request, body: bytes):
    """Publish a body already read for this request to the middlewares above.

    Every `BaseHTTPMiddleware` layer builds its own `Request`, and the body one of them caches is
    replayed downwards but is invisible upwards: the outer layer holds a different object, and by
    the time it runs again the stream is gone. The ASGI scope is the one thing both layers share,
    so the bytes travel up through the `extensions` dict the access logger creates before
    dispatching -- the same channel that carries the authenticated identity back out.

    Parameters
    ----------
    request : Request
        HTTP request.
    body : bytes
        Body already read for this request.
    """
    request.scope.setdefault('extensions', {})[CACHED_BODY_KEY] = body


def get_cached_body(request: Request) -> Optional[bytes]:
    """Get the body an inner middleware published for this request.

    Parameters
    ----------
    request : Request
        HTTP request.

    Returns
    -------
    Optional[bytes]
        Body read below, or None when no layer published one and the stream was left to the endpoint.
    """
    return request.scope.get('extensions', {}).get(CACHED_BODY_KEY)


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
    # above the security handler from the same code returned to an authenticated caller further
    # down. `WazuhAccessLoggerMiddleware` is what makes the context readable from out here.
    log_body = bool(context.get('user', None) or context.get('token_info', None))

    # The body is deserialised here, after the response, and no longer in the middleware before the
    # request was dispatched: nothing should build an object graph out of a payload for a caller
    # nobody has authenticated yet. It is parsed only where the result is used -- written to the
    # logs, or hashed into a run_as auth context identifier -- and only from bytes the middleware
    # already cached, never by reading the stream again. This runs after the response has been
    # produced, so a payload that will not parse degrades to an empty body rather than turning a
    # served response into a 500.
    body_read = hasattr(request, '_body')
    body = {}
    if body_read and (log_body or path == RUN_AS_LOGIN_ENDPOINT):
        try:
            body = await request.json()
        except RecursionError:
            body = {}

    if 'password' in query:
        query['password'] = '****'
    # A JSON body is not necessarily an object: `null`, a list and bare scalars are all valid JSON,
    # and only a mapping can carry the fields masked below. Testing membership on any of the others
    # raises a TypeError here, which turned the validator's 400 into a 500.
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
        # `WazuhInternalError` covers a keypair that could not be read (6003). This runs after the
        # response has already been produced, so a transient failure here must degrade the logged
        # username, never turn a served response into a 500.
        except (KeyError, IndexError, binascii.Error, jwt.exceptions.PyJWTError, OAuthProblem,
                WazuhInternalError):
            user = UNKNOWN_USER_STRING

    # custom_logging() escapes every field it writes; this only flags the attempt.
    if user and user != UNKNOWN_USER_STRING and control_chars_pattern.search(user):
        logger.warning(
            f'Username contains control characters. User: {user!r}, IP: {host}, '
            f'Path: {escape_control_chars(path)}.'
        )

    # Create hash if run_as login. Only from an auth context that was actually read: hashing the
    # empty body that stands in for a payload no layer cached would stamp every such attempt with
    # the same constant, valid-looking digest instead of leaving the field empty.
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


async def check_blocked_ip(request: Request):
    """Blocks/unblocks the IPs that are requesting an API token, counting the attempt.

    The attempt is counted in the same locked section that checks the block, before the
    request is dispatched to authentication, so concurrent requests observe each other's
    in-flight attempts instead of only already-recorded failures.

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
    max_login_attempts = access_conf['max_login_attempts']
    host = request.client.host

    async with ip_lock:
        try:
            if get_utc_now().timestamp() - block_time >= ip_stats[host]['timestamp']:
                del ip_stats[host]
                ip_block.remove(host)
        except (KeyError, ValueError):
            pass

        if host in ip_block:
            raise BlockedIPException(
                status=403,
                title="Permission Denied",
                detail="Limit of login attempts reached. The current IP has been blocked due "
                       "to a high number of login attempts"
            )

        if host not in ip_stats:
            ip_stats[host] = {'attempts': 1}
        else:
            ip_stats[host]['attempts'] += 1
        ip_stats[host]['timestamp'] = get_utc_now().timestamp()

        if ip_stats[host]['attempts'] >= max_login_attempts:
            ip_block.add(host)


async def settle_login_attempt(request: Request):
    """Release the attempt reserved by `check_blocked_ip` for a successful login.

    Only failed login attempts should count towards `max_login_attempts`, so a
    successful authentication releases the attempt that was counted at the gate
    before credential validation ran.

    Parameters
    ----------
    request : Request
        HTTP request.
    """
    global ip_block, ip_stats
    max_login_attempts = configuration.api_conf['access']['max_login_attempts']
    host = request.client.host

    async with ip_lock:
        if host not in ip_stats:
            return

        ip_stats[host]['attempts'] -= 1
        if ip_stats[host]['attempts'] < max_login_attempts:
            ip_block.discard(host)


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
        0 if the request is allowed
        else error_code.
    """
    if max_requests == 0:
        return 0

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

        if error_code:
            raise MaxRequestsException(code=error_code)
        else:
            return await call_next(request)


class CheckAuthContextSizeMiddleware(BaseHTTPMiddleware):
    """Reject run_as requests whose body exceeds AUTH_CONTEXT_MAX_PAYLOAD_SIZE."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Refuse an oversized auth context without paying for it first.

        The declared `Content-Length` is checked before the body is touched, so a payload a
        thousand times the endpoint's limit is refused at the header. A request that declares no
        length is read with a cap and abandoned at the limit, rather than materialised in full and
        measured afterwards.

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
        if request.url.path == RUN_AS_LOGIN_ENDPOINT and request.method == "POST":
            detail = f"Auth context payload exceeds the maximum allowed size of " \
                     f"{AUTH_CONTEXT_MAX_PAYLOAD_SIZE} bytes."
            declared_length = get_declared_content_length(request)
            if declared_length is None:
                # This is the only layer that reads a chunked auth context, and the access logger
                # above it will never see the stream, so the bytes are handed over explicitly.
                # Without this, a chunked run_as attempt is logged with an empty body.
                set_cached_body(request,
                                await read_capped_body(request, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, detail))
            elif declared_length > AUTH_CONTEXT_MAX_PAYLOAD_SIZE:
                raise PayloadTooLargeException(title="Request Entity Too Large", detail=detail)
        return await call_next(request)


class CheckBlockedIP(BaseHTTPMiddleware):
    """Rate Limits Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """"Update and check if the client IP is locked."""
        if request.url.path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} \
           and request.method in {'GET', 'POST'}:
            await check_blocked_ip(request)
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

        # connexion's routing middleware passes a shallow copy of the scope downwards, so the
        # request context that the security handler writes into the copy's `extensions` is invisible
        # from out here -- which is why the username below has to be recovered from the authorization
        # header. Creating `extensions` before the request is dispatched makes the copy share this
        # very dict, so `access_log` can read the identity the security handler settled on and does
        # not have to guess it from the response status.
        request.scope.setdefault('extensions', {})

        # This is the outermost middleware, so reading every body here handed an unauthenticated
        # caller a max_upload_size buffer plus the object graph deserialised from it, once per
        # request, before the security handler had been asked who was calling.
        #
        # Only the bytes are buffered, and only when they are small enough to be worth logging.
        # `access_log` runs after the response, when the stream is gone, so they have to be cached
        # here for it to report them; the deserialisation is deferred to `access_log`, which by then
        # knows whether the result is needed at all. Reading is bounded by the declared length, since
        # the ASGI server never delivers more body than the request declares; a request that declares
        # none, or declares more than is worth logging, is left for the endpoint to read and its body
        # does not reach the log.
        content_length = get_declared_content_length(request)
        if content_length is not None and 0 < content_length <= MAX_LOGGED_BODY_SIZE:
            # Related to https://github.com/wazuh/wazuh/issues/24060.
            await request.body()

        response = await call_next(request)

        # A chunked run_as auth context is read by `CheckAuthContextSizeMiddleware`, which caps it
        # while reading because there is no length to check. That happens below this layer, and a
        # body cached in one `BaseHTTPMiddleware` request travels downwards only, so adopt the
        # bytes it published; otherwise the attempt is logged, and hashed, as an empty body.
        if not hasattr(request, '_body') and (cached_body := get_cached_body(request)) is not None:
            request._body = cached_body

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
                max_upload_size = configuration.api_conf["max_upload_size"]
                if content_length > max_upload_size:
                    raise ExpectFailedException(status=417, title="Expectation failed",
                                                detail=f"Maximum content size limit ({max_upload_size}) exceeded "
                                                       f"({content_length} bytes read)")

        response = await call_next(request)
        return response
