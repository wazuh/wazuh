# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock, call
import binascii
import hashlib
import json
import logging
import jwt
import pytest

from starlette.requests import Request
from starlette.responses import Response

from connexion import AsyncApp
from connexion.middleware import MiddlewarePosition
from content_size_limit_asgi import ContentSizeLimitMiddleware
from connexion.testing import TestContext
from connexion.exceptions import ProblemException, OAuthProblem

from freezegun import freeze_time

from api.middlewares import check_rate_limit, check_blocked_ip, settle_login_attempt, UNKNOWN_USER_STRING, \
    MAX_REQUESTS_EVENTS_DEFAULT, LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, \
    CheckAuthContextSizeMiddleware, CheckRateLimitsMiddleware, WazuhAccessLoggerMiddleware, CheckBlockedIP, \
    SecureHeadersMiddleware, CheckExpectHeaderMiddleware, secure_headers, access_log, get_declared_content_length, \
    read_capped_body, CACHED_BODY_KEY, setup_middlewares, AUTH_CONTEXT_NOT_LOGGED
from api.alogging import MAX_LOGGED_BODY_SIZE
from api.api_exception import ExpectFailedException, PayloadTooLargeException

def build_request(path='/agents', method='POST', content_length=None, receive=None):
    """Build a real starlette request, so what the middlewares read from the socket is observable.

    Parameters
    ----------
    path : str
        Request path.
    method : str
        HTTP method.
    content_length : int
        Value of the `Content-Length` header. Omitted when None, as a chunked request would.
    receive : Callable
        ASGI receive channel.

    Returns
    -------
    Request
        HTTP request.
    """
    headers = [(b'content-type', b'application/json')]
    if content_length is not None:
        headers.append((b'content-length', str(content_length).encode()))

    return Request(
        {
            'type': 'http',
            'http_version': '1.1',
            'method': method,
            'scheme': 'https',
            'server': ('localhost', 55000),
            'client': ('ip', 1234),
            'root_path': '',
            'path': path,
            'raw_path': path.encode(),
            'query_string': b'',
            'headers': headers,
        },
        receive or AsyncMock(side_effect=AssertionError('the request body was read')),
    )


def chunked_receive(chunk, chunks):
    """Build an ASGI receive channel that streams `chunk` `chunks` times.

    Parameters
    ----------
    chunk : bytes
        Body chunk to deliver on every call.
    chunks : int
        Number of chunks the body is split into.

    Returns
    -------
    AsyncMock
        ASGI receive channel.
    """
    return AsyncMock(side_effect=[
        {'type': 'http.request', 'body': chunk, 'more_body': index < chunks - 1}
        for index in range(chunks)
    ])


@pytest.fixture
def mock_req():
    """fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    req.json = AsyncMock(side_effect=lambda: {'ctx': ''} )
    req.context = MagicMock()
    req.context.get = MagicMock(return_value={})
    req.body = AsyncMock(return_value=b'x' * (AUTH_CONTEXT_MAX_PAYLOAD_SIZE + 1))

    return req


@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.asyncio
async def test_middlewares_check_blocked_ip(mock_req):
    """Test check_blocked_ip function.
       Check if the ip_block is emptied when the blocking period has finished, and that the
       current attempt is then counted."""
    api_conf = {'access': {'block_time': 300, 'max_login_attempts': 50}}
    with patch("api.middlewares.ip_stats", new={'ip': {'timestamp': -300}}) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new={"ip"}) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new=api_conf):
        await check_blocked_ip(mock_req)
        assert "ip" not in mock_ip_block
        assert mock_ip_stats == {'ip': {'attempts': 1, 'timestamp': 10.0}}


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_check_blocked_ip_ko(mock_req):
    """Test if `check_blocked_ip` raises an exception if the IP is still blocked."""
    with patch('api.middlewares.ConnexionRequest.from_starlette_request', returns_value=mock_req):
        with pytest.raises(ProblemException) as exc_info:
            await check_blocked_ip(mock_req)

    assert exc_info.value.status == 403
    assert exc_info.value.title == "Permission Denied"
    assert exc_info.value.detail == (
        "Limit of login attempts reached. The current IP has been blocked due "
        "to a high number of login attempts"
    )
    assert exc_info.value.ext == {'code': 6000}


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize('stats, expected_attempts, expect_blocked', [
    ({}, 1, False),
    ({'ip': {'attempts': 3, 'timestamp': 10}}, 4, False),
    ({'ip': {'attempts': 4, 'timestamp': 10}}, 5, True),
])
async def test_middlewares_check_blocked_ip_counts_attempt(
        stats, expected_attempts, expect_blocked, mock_req):
    """Test that `check_blocked_ip` counts the current attempt atomically with the block
       check (before authentication runs), and blocks the IP once max_login_attempts is
       reached."""
    api_conf = {'access': {'block_time': 300, 'max_login_attempts': 5}}
    with patch("api.middlewares.ip_stats", new=dict(stats)) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new=set()) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new=api_conf):
        await check_blocked_ip(mock_req)

        assert mock_ip_stats['ip']['attempts'] == expected_attempts
        assert mock_ip_stats['ip']['timestamp'] == datetime(1970, 1, 1, 0, 0, 10).timestamp()
        assert ('ip' in mock_ip_block) == expect_blocked


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_check_blocked_ip_enforces_limit_without_auth_failure(mock_req):
    """Regression test for the check-then-count race: the block must trigger purely from
       attempts counted at the gate, without any request having reached credential
       validation or the (now removed) post-auth counter. This closes the window that
       concurrent requests previously used to bypass max_login_attempts."""
    api_conf = {'access': {'block_time': 300, 'max_login_attempts': 3}}
    with patch("api.middlewares.ip_stats", new={}) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new=set()) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new=api_conf):
        await check_blocked_ip(mock_req)
        await check_blocked_ip(mock_req)
        await check_blocked_ip(mock_req)

        assert mock_ip_stats['ip']['attempts'] == 3
        assert "ip" in mock_ip_block

        with pytest.raises(ProblemException) as exc_info:
            await check_blocked_ip(mock_req)
        assert exc_info.value.status == 403


@pytest.mark.asyncio
@pytest.mark.parametrize('stats, max_login_attempts, expected_attempts, expect_blocked', [
    ({'ip': {'attempts': 1, 'timestamp': 10}}, 5, 0, False),
    ({'ip': {'attempts': 3, 'timestamp': 10}}, 5, 2, False),
    ({'ip': {'attempts': 5, 'timestamp': 10}, }, 5, 4, False),
])
async def test_middlewares_settle_login_attempt(
        stats, max_login_attempts, expected_attempts, expect_blocked, mock_req):
    """Test that `settle_login_attempt` releases the attempt reserved by `check_blocked_ip`
       for a successful login, and unblocks the IP if the release brings it back under
       max_login_attempts."""
    api_conf = {'access': {'block_time': 300, 'max_login_attempts': max_login_attempts}}
    starting_block = {'ip'} if stats['ip']['attempts'] >= max_login_attempts else set()
    with patch("api.middlewares.ip_stats", new=dict(stats)) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new=starting_block) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new=api_conf):
        await settle_login_attempt(mock_req)

        assert mock_ip_stats['ip']['attempts'] == expected_attempts
        assert ('ip' in mock_ip_block) == expect_blocked


@pytest.mark.asyncio
async def test_middlewares_settle_login_attempt_unknown_host(mock_req):
    """Test that `settle_login_attempt` is a no-op for a host with no recorded attempts."""
    with patch("api.middlewares.ip_stats", new={}) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new=set()) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new={'access': {'max_login_attempts': 5}}):
        await settle_login_attempt(mock_req)

        assert mock_ip_stats == {}
        assert mock_ip_block == set()


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_repeated_successful_logins_never_block_ip(mock_req):
    """Regression test: a client authenticating frequently from a single IP (NAT, load
       balancer, token-per-call automation) must never be blocked as long as every attempt
       succeeds, since check_blocked_ip's reservation is released by settle_login_attempt
       on each successful login."""
    api_conf = {'access': {'block_time': 300, 'max_login_attempts': 3}}
    with patch("api.middlewares.ip_stats", new={}) as mock_ip_stats, \
         patch("api.middlewares.ip_block", new=set()) as mock_ip_block, \
         patch("api.middlewares.configuration.api_conf", new=api_conf):
        for _ in range(20):
            await check_blocked_ip(mock_req)
            await settle_login_attempt(mock_req)

        assert mock_ip_stats['ip']['attempts'] == 0
        assert "ip" not in mock_ip_block


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize("current_time,max_requests,current_time_key, current_counter_key,expected_error_code", [
    (-80, 300, 'events_current_time', 'events_request_counter', 0),
    (-80, 300, 'general_current_time', 'general_request_counter', 0),
    (0, 0, 'events_current_time', 'events_request_counter', 0),
    (0, 0, 'general_current_time', 'general_request_counter', 0),
])
def test_middlewares_check_rate_limit(
    current_time, max_requests, current_time_key, current_counter_key,
    expected_error_code, mock_req):
    """Test if the rate limit mechanism triggers when the `max_requests` are reached."""

    with patch(f"api.middlewares.{current_time_key}", new=current_time):
        code = check_rate_limit(
            current_time_key=current_time_key,
            request_counter_key=current_counter_key,
            max_requests=max_requests,
            error_code=expected_error_code)
        assert code == expected_error_code


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ['/agents', '/events'])
async def test_check_rate_limits_middleware(endpoint, mock_req):
    """Test limits middleware."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    rq_x_min = 10000
    api_conf = {'access': { 'max_request_per_minute': rq_x_min }}
    with TestContext(operation=operation), \
        patch('api.middlewares.check_rate_limit', return_value=0) as mock_check, \
        patch('api.middlewares.configuration.api_conf', new=api_conf):
        await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        if endpoint == '/events':
            mock_check.assert_has_calls([
                call('general_request_counter', 'general_current_time', rq_x_min, 6001),
                call('events_request_counter', 'events_current_time', MAX_REQUESTS_EVENTS_DEFAULT, 6005),
            ], any_order=False)
        else:
            mock_check.assert_called_once_with(
                'general_request_counter', 'general_current_time', rq_x_min, 6001)
        dispatch_mock.assert_awaited()


@freeze_time(datetime(1970, 1, 1))
def test_check_rate_limit_disabled():
    """Check that rate limit is disabled when max_requests is 0."""
    code = check_rate_limit(
        request_counter_key='general_request_counter',
        current_time_key='general_current_time',
        max_requests=0,
        error_code=6001
    )
    assert code == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint, return_values, expected_calls, expected_code", [
    ('/agents', [6001], 1, 6001),
    ('/events', [0, 6005], 2, 6005),
    ('/events', [6001], 1, 6001),
])
async def test_check_rate_limits_middleware_ko(
    endpoint, return_values, expected_calls, expected_code, mock_req):
    """Test limits middleware."""
    return_value_sequence = return_values.copy()

    def check_rate_limit_side_effect(*_):
        """Side effect function."""
        return return_value_sequence.pop(0)

    dispatch_mock = AsyncMock()
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    rq_x_min = 10000
    api_conf = {'access': {'max_request_per_minute': rq_x_min}}
    with TestContext(operation=operation), \
        patch('api.middlewares.ConnexionRequest.from_starlette_request',
              return_value=mock_req) as mock_from, \
        patch('api.middlewares.configuration.api_conf', api_conf), \
        patch('api.middlewares.check_rate_limit', side_effect=check_rate_limit_side_effect) as mock_check, \
        pytest.raises(ProblemException) as exc_info:
        await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_from.assert_called_once_with(mock_req)
        dispatch_mock.assert_not_awaited()
        assert exc_info.value.status == 429
        assert mock_check.call_count == expected_calls
        assert exc_info.value.ext['code'] == expected_code


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize("json_body, q_password, b_password, b_key, c_user, hash, sec_header, endpoint, method, status_code", [
    (True, None, None, None, None, 'hash', ('basic', 'wazuh:pwd'), '/agents', 'GET', 200),
    (False, 'q_pass', 'b_pass', 'b_key', 'wazuh', '', ('basic', 'wazuh:pwd'), LOGIN_ENDPOINT, 'GET', 200),
    (False, None, 'b_pass', 'b_key', 'wazuh', '', ('bearer', {'sub':'wazuh'}), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
    (False, 'q_pass', None, 'b_key', 'wazuh', '', ('bearer', {'sub':'wazuh'}), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
    (False, 'q_pass', None, 'b_key', 'wazuh', '', ('other', ''), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
])
async def test_access_log(json_body, q_password, b_password, b_key, c_user,
                          hash, sec_header, endpoint, method, status_code, mock_req):
    """Test access_log function."""
    JWT_ALGORITHM = 'ES512'
    response = MagicMock()
    response.status_code = status_code

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    body.update({'password': 'b_password'} if b_password else {})
    body.update({'key': b_key} if b_key else {})
    if json_body:
        mock_req._json = MagicMock()
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {'password': q_password} if q_password else {}
    mock_req.method = method
    mock_req.context = {
        'token_info': {'hash_auth_context': hash} if hash else {},
    }
    mock_req.context.update({'user': c_user} if c_user else {})
    mock_req.scope = {'path': endpoint}
    mock_req.headers = {'content-type': 'None'}
    mock_blacke2b = MagicMock()
    mock_blacke2b.return_value.hexdigest.return_value = f"blackeb2 {hash}"
    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('hashlib.blake2b', mock_blacke2b), \
        patch('api.middlewares.base64.b64decode', return_value=sec_header[1].encode("latin1") \
                  if isinstance(sec_header[1], str) else '') as mock_b64decode, \
        patch('api.middlewares.jwt.decode',
              return_value=sec_header[1])  as mock_jwt_decode, \
        patch('api.middlewares.generate_keypair',
              return_value=(None, None)) as mock_generate_keypair, \
        patch('api.middlewares.logger.warning',
              return_value=(None, None)) as mock_log_warning, \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value',
              return_value=sec_header) as mock_get_headers:
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)
        if json_body:
            mock_req.json.assert_awaited_once()
        expected_user = UNKNOWN_USER_STRING if not c_user and not sec_header[0] else 'wazuh'
        if not c_user:
            mock_get_headers.assert_called_once_with(mock_req)
            if sec_header[0] == 'basic':
                mock_b64decode.assert_called_once_with(sec_header[1])
            elif sec_header[0] == 'bearer':
                mock_generate_keypair.assert_called_once()
                mock_jwt_decode.assert_called_once_with(sec_header[1], None, [JWT_ALGORITHM])

        if not hash and endpoint == RUN_AS_LOGIN_ENDPOINT:
            mock_blacke2b.assert_called_once()
            hash = f"blackeb2 {hash}"
        mock_req.query_params.update({'password': '****'} if q_password else {})
        body.update({'password': '****'} if b_key else {})
        body.update({'key': '****'} if b_key and endpoint == '/agents' else {})
        # The body is logged only for a caller the security handler accepted, which the fixture
        # signals through the request context, and an accepted auth context is replaced by a
        # placeholder unless debug logging is on.
        if not c_user:
            expected_body = {}
        elif endpoint == RUN_AS_LOGIN_ENDPOINT:
            expected_body = {'auth_context': AUTH_CONTEXT_NOT_LOGGED}
        else:
            expected_body = body
        mock_custom_logging.assert_called_once_with(
            expected_user, mock_req.client.host, mock_req.method,
            endpoint, mock_req.query_params, expected_body, 0.0, response.status_code,
            hash_auth_context=hash, headers=mock_req.headers
        )
        if status_code == 403 and \
            endpoint in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and \
                method in {'GET', 'POST'}:
            mock_log_warning.assert_called_once_with(
                f"IP blocked due to exceeded number of logins attempts: {mock_req.client.host}")


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_hash_auth_context(mock_req):
    """Check that `access_log` obtains the authentication context hash from the JWT token."""
    response = MagicMock()
    response.status_code = 200
    user = 'wazuh'
    hash_auth_context = '5a5e646ea0bc6e3653cfc593d62b16f7'
    sec_header = ('bearer', {'sub': user, 'hash_auth_context': hash_auth_context})
    body = {}
    endpoint = '/agents'

    mock_req.json = AsyncMock(return_value=body)
    mock_req.method = 'GET'
    mock_req.scope = {'path': endpoint}
    mock_req.headers = {}
    mock_req.query_params = {}

    with patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('api.middlewares.jwt.decode', return_value=sec_header[1]), \
        patch('api.middlewares.generate_keypair', return_value=(None, None)), \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header):
        await access_log(request=mock_req, response=response, prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

        mock_custom_logging.assert_called_once_with(
            user, mock_req.client.host, mock_req.method, endpoint, mock_req.query_params, body, 0.0,
            response.status_code, hash_auth_context=hash_auth_context, headers=mock_req.headers
        )


@freeze_time(datetime(1970, 1, 1, 0, 0, 0))
@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [
    (OAuthProblem),
    (jwt.exceptions.PyJWTError),
    (KeyError),
    (IndexError),
    (binascii.Error)
])
async def test_access_log_ko(mock_req, exception):
    """Test access_log authorization header decoding exceptions."""
    user = UNKNOWN_USER_STRING
    endpoint = LOGIN_ENDPOINT
    method = 'GET'
    status_code = 401

    response = MagicMock()
    response.status_code = status_code

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {'password': '****'}
    mock_req.method = method
    mock_req.context.update({'user': user})
    mock_req.scope = {'path': endpoint}
    mock_req.headers = {'content-type': 'None'}

    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', side_effect=exception):
        expected_time = datetime(1970, 1, 1, 0, 0, 0).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)
        mock_custom_logging.assert_called_once_with(
            user, mock_req.client.host, mock_req.method,
            endpoint, mock_req.query_params, body, 0.0, response.status_code,
            hash_auth_context='', headers=mock_req.headers
        )


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_wazuh_access_logger_middleware():
    """Test access logger middleware."""
    mock_req = AsyncMock()
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)

    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)
    operation = MagicMock(name="operation")
    operation.method = "post"

    with TestContext(operation=operation), \
        patch('api.middlewares.access_log') as mock_access_log, \
        patch('api.middlewares.ConnexionRequest.from_starlette_request',
              return_value=mock_req) as mock_from:
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        resp = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_from.assert_called_once_with(mock_req)
        mock_access_log.assert_called_once_with(mock_req, response, expected_time)
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert resp == response


@pytest.mark.parametrize('content_length, expected', [
    ('1024', 1024),
    ('0', 0),
    (None, None),
    ('not-a-number', None),
    ('-1', None),
])
def test_get_declared_content_length(content_length, expected):
    """Check that the declared body length is read from the header and unusable values ignored."""
    request = MagicMock()
    request.headers = {'content-length': content_length} if content_length is not None else {}

    assert get_declared_content_length(request) == expected


@pytest.mark.asyncio
async def test_read_capped_body():
    """Check that a body within the limit is read in full and cached for the rest of the stack."""
    request = build_request(receive=chunked_receive(b'a' * 16, 4))

    assert await read_capped_body(request, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, 'too large') == b'a' * 64
    # Cached the way `Request.body()` caches it, so the body is still replayed downstream.
    assert request._body == b'a' * 64
    # Reading it again does not touch the socket.
    assert await read_capped_body(request, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, 'too large') == b'a' * 64


@pytest.mark.asyncio
async def test_read_capped_body_ko():
    """Check that `read_capped_body` abandons the stream instead of buffering the whole body."""
    # Ten times the limit, in chunks of an eighth of it.
    chunk_size = AUTH_CONTEXT_MAX_PAYLOAD_SIZE // 8
    receive = chunked_receive(b'a' * chunk_size, 80)
    request = build_request(receive=receive)

    with pytest.raises(PayloadTooLargeException) as exc_info:
        await read_capped_body(request, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, 'too large')

    assert exc_info.value.status == 413
    assert exc_info.value.detail == 'too large'
    # It stopped on the chunk that crossed the limit, not at the end of the body.
    assert receive.await_count == 9


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_does_not_read_oversized_body():
    """Check that the access logger does not read a body too large to be logged.

    This is the root cause of the memory footprint an unauthenticated caller used to be able to
    set: the middleware is the outermost one, so a body buffered and deserialised here is paid for
    before the security handler has been consulted. `build_request` fails the read, so the
    assertion is that nothing is pulled from the socket at all.
    """
    response = MagicMock()
    response.status_code = 401
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(content_length=9 * 1024 * 1024)
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log') as mock_access_log, \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request):
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    assert not hasattr(request, '_body')
    assert not hasattr(request, '_json')
    mock_access_log.assert_called_once()


@pytest.mark.parametrize('content_length', [
    None,  # A chunked request declares no length, so there is no bound on what reading would cost.
    0,
])
@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_does_not_read_undeclared_body(content_length):
    """Check that the access logger only reads a body whose size the request declares."""
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(content_length=content_length)
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request):
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    assert not hasattr(request, '_json')


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_reads_loggable_body():
    """Check that a body small enough to be logged is still parsed before the stream is consumed."""
    body = b'{"a": "b"}'
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(content_length=len(body), receive=chunked_receive(body, 1))
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request):
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    # Cached for `access_log` to report, but not deserialised: nothing has authenticated the caller
    # at this point, so the object graph is not built here.
    assert request._body == body
    assert not hasattr(request, '_json')


@pytest.mark.parametrize('body', [
    b'{"a": ',                          # unparsable
    b'[' * 4000 + b']' * 4000,          # nested past the interpreter's recursion limit
])
@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_does_not_parse(body):
    """Check that the middleware buffers a body without ever deserialising it."""
    response = MagicMock()
    response.status_code = 400
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(content_length=len(body), receive=chunked_receive(body, 1))
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request):
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    assert not hasattr(request, '_json')


@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_rejects_declared_length():
    """Check that an oversized auth context is refused at the header, before it is read."""
    dispatch_mock = AsyncMock()
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, content_length=9 * 1024 * 1024)
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with pytest.raises(PayloadTooLargeException) as exc_info:
        await middleware.dispatch(request=request, call_next=dispatch_mock)

    assert exc_info.value.status == 413
    assert exc_info.value.detail == f'Auth context payload exceeds the maximum allowed size of ' \
                                   f'{AUTH_CONTEXT_MAX_PAYLOAD_SIZE} bytes.'
    dispatch_mock.assert_not_awaited()
    assert not hasattr(request, '_body')


@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_caps_undeclared_length():
    """Check that an auth context declaring no length is capped as it is read, not afterwards."""
    chunk_size = AUTH_CONTEXT_MAX_PAYLOAD_SIZE // 8
    receive = chunked_receive(b'a' * chunk_size, 80)
    dispatch_mock = AsyncMock()
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, receive=receive)
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with pytest.raises(PayloadTooLargeException) as exc_info:
        await middleware.dispatch(request=request, call_next=dispatch_mock)

    assert exc_info.value.status == 413
    dispatch_mock.assert_not_awaited()
    assert receive.await_count == 9


@pytest.mark.parametrize('path, content_length, receive_chunks', [
    # An auth context within the limit: nothing to read when the length is declared, capped read
    # when it is not.
    (RUN_AS_LOGIN_ENDPOINT, AUTH_CONTEXT_MAX_PAYLOAD_SIZE, 0),
    (RUN_AS_LOGIN_ENDPOINT, None, 1),
    # Every other endpoint is left alone, whatever it declares.
    ('/agents', 9 * 1024 * 1024, 0),
    ('/agents', None, 0),
])
@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_allowed(path, content_length, receive_chunks):
    """Check that the auth context limit does not stand in the way of the requests it does not own."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    receive = chunked_receive(b'{"a": "b"}', 1) if receive_chunks else None
    request = build_request(path=path, content_length=content_length, receive=receive)
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response
    assert (receive.await_count if receive else 0) == receive_chunks


@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_publishes_the_capped_body():
    """Check that the body read here is published for the access logger, which sits above."""
    body = b'{"auth": "context"}'
    dispatch_mock = AsyncMock(return_value=MagicMock())
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, receive=chunked_receive(body, 1))
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    await middleware.dispatch(request=request, call_next=dispatch_mock)

    assert request.scope['extensions'][CACHED_BODY_KEY] == body


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_adopts_a_body_read_below():
    """Check that a body only an inner middleware could read still reaches the log.

    A chunked run_as auth context is read by `CheckAuthContextSizeMiddleware`, below this layer,
    and a body cached in one `BaseHTTPMiddleware` request is replayed downwards but is invisible
    upwards. Without the hand-off through the scope, the attempt would be logged as an empty body.
    """
    body = b'{"auth": "context"}'
    response = MagicMock()
    response.status_code = 200

    async def call_next(request):
        # What `CheckAuthContextSizeMiddleware` does with the chunked body it caps.
        request.scope['extensions'][CACHED_BODY_KEY] = body
        return response

    request = build_request(path=RUN_AS_LOGIN_ENDPOINT)
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=call_next)

    with patch('api.middlewares.access_log') as mock_access_log:
        assert await middleware.dispatch(request=request, call_next=call_next) == response

    assert request._body == body
    assert await mock_access_log.call_args.args[0].json() == {'auth': 'context'}


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_keeps_the_body_it_read_itself():
    """Check that a published body never overwrites the bytes this layer already read."""
    body = b'{"a": "b"}'
    response = MagicMock()

    async def call_next(request):
        request.scope['extensions'][CACHED_BODY_KEY] = b'{"other": "body"}'
        return response

    request = build_request(content_length=len(body), receive=chunked_receive(body, 1))
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=call_next)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request):
        assert await middleware.dispatch(request=request, call_next=call_next) == response

    assert request._body == body


@pytest.mark.parametrize('context, status_code, path, expected_body', [
    # The security handler accepted the caller, so the payload is worth auditing -- whatever status
    # the request ends up with. 404 (a group that does not exist), 413 (above max_upload_size) and
    # 417 (a rejected Expect header) are all reachable only from below the security handler, and
    # were previously misread as unauthenticated because they were judged by status code alone.
    ({'user': 'wazuh', 'token_info': {}}, 200, '/agents', {'field': 'value'}),
    ({'user': 'wazuh', 'token_info': {}}, 400, '/agents', {'field': 'value'}),
    ({'user': 'wazuh', 'token_info': {}}, 403, '/agents', {'field': 'value'}),
    ({'user': 'wazuh', 'token_info': {}}, 404, '/groups/x/configuration', {'field': 'value'}),
    ({'user': 'wazuh', 'token_info': {}}, 413, '/agents', {'field': 'value'}),
    ({'user': 'wazuh', 'token_info': {}}, 417, '/agents', {'field': 'value'}),
    ({'token_info': {'rbac_policies': {}}}, 200, '/agents', {'field': 'value'}),
    # Nobody vouched for these payloads, so they must not reach api.log or api.json.
    ({}, 401, '/agents', {}),
    ({}, 405, '/agents', {}),
    ({}, 429, '/agents', {}),
    ({}, 413, RUN_AS_LOGIN_ENDPOINT, {}),
    ({}, 403, LOGIN_ENDPOINT, {}),
])
@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_omits_unauthenticated_body(context, status_code, path, expected_body,
                                                     mock_req):
    """Check that the body is logged for an authenticated caller and omitted otherwise."""
    response = MagicMock()
    response.status_code = status_code
    mock_req._body = b'{"field": "value"}'
    mock_req.json = AsyncMock(return_value={'field': 'value'})
    mock_req.query_params = {}
    mock_req.method = 'POST'
    mock_req.context = context
    mock_req.scope = {'path': path}
    mock_req.headers = {'content-type': 'application/json'}

    with patch('api.middlewares.custom_logging') as mock_custom_logging, \
         patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value',
               side_effect=OAuthProblem):
        await access_log(request=mock_req, response=response,
                         prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

    assert mock_custom_logging.call_args.args[5] == expected_body


@pytest.mark.parametrize('context, path, should_parse', [
    # Reached the endpoint: the body is logged, so it has to be parsed.
    ({'user': 'wazuh'}, '/agents', True),
    # Never authenticated: nothing will use the body, so it is not deserialised at all. This is
    # what keeps an unauthenticated caller from paying for `json.loads` on a payload nobody
    # vouched for.
    ({}, '/agents', False),
    # A failed run_as is still hashed into an auth context identifier, which needs the parse.
    ({}, RUN_AS_LOGIN_ENDPOINT, True),
])
@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_only_parses_the_body_it_uses(context, path, should_parse, mock_req):
    """Check that the body is deserialised only where the result is actually used."""
    response = MagicMock()
    response.status_code = 200
    mock_req._body = b'{"field": "value"}'
    mock_req.json = AsyncMock(return_value={'field': 'value'})
    mock_req.query_params = {}
    mock_req.method = 'POST'
    mock_req.context = context
    mock_req.scope = {'path': path}
    mock_req.headers = {'content-type': 'application/json'}

    with patch('api.middlewares.custom_logging'), \
         patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value',
               side_effect=OAuthProblem):
        await access_log(request=mock_req, response=response,
                         prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

    assert mock_req.json.await_count == (1 if should_parse else 0)


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_survives_an_unparsable_body(mock_req):
    """Check that a body that will not parse does not turn a served response into a 500.

    `access_log` runs after the response has been produced, and now owns the deserialisation, so a
    payload the endpoint already rejected must not raise here.
    """
    response = MagicMock()
    response.status_code = 200
    mock_req._body = b'[' * 4000
    mock_req.json = AsyncMock(side_effect=RecursionError)
    mock_req.query_params = {}
    mock_req.method = 'POST'
    # An authenticated caller, so access_log actually deserialises and the RecursionError handler
    # is exercised; with an empty context the parse is skipped and the handler never runs.
    mock_req.context = {'user': 'wazuh'}
    mock_req.scope = {'path': '/agents'}
    mock_req.headers = {'content-type': 'application/json'}

    with patch('api.middlewares.custom_logging') as mock_custom_logging, \
         patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value',
               side_effect=OAuthProblem):
        await access_log(request=mock_req, response=response,
                         prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

    assert mock_req.json.await_count == 1
    assert mock_custom_logging.call_args.args[5] == {}


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize("parsed_body", [None, ['a', 'b'], 'a string', 42, True])
async def test_access_log_masking_survives_a_non_dict_body(mock_req, parsed_body):
    """An authenticated request whose small cached body parses to a non-dict must not raise.

    The field-masking below reads and assigns into the parsed body; only a mapping supports that.
    request.json() returns None for a malformed/null/binary payload and a non-dict for a JSON list
    or scalar, and access_log runs after the response, so a raise here would be a 500 for a request
    already served and would drop its log line.
    """
    response = MagicMock()
    response.status_code = 200
    mock_req._body = b'"whatever"'
    mock_req.json = AsyncMock(return_value=parsed_body)
    mock_req.query_params = {}
    mock_req.method = 'POST'
    mock_req.context = {'user': 'wazuh'}
    mock_req.scope = {'path': '/agents'}
    mock_req.headers = {'content-type': 'application/json'}

    with patch('api.middlewares.custom_logging') as mock_custom_logging:
        await access_log(request=mock_req, response=response,
                         prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

    mock_custom_logging.assert_called_once()
    assert mock_custom_logging.call_args.args[5] == parsed_body


@pytest.mark.asyncio
async def test_secure_headers_middleware(mock_req):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = SecureHeadersMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"

    with TestContext(operation=operation), patch('api.middlewares.secure_headers') as mock_secure:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_secure.framework.starlette.assert_called_once_with(response)
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert ret_response == response


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint, method, call_check", [
    (LOGIN_ENDPOINT, 'POST', True),
    (RUN_AS_LOGIN_ENDPOINT, 'POST', True),
    (LOGIN_ENDPOINT, 'GET', True),
    (RUN_AS_LOGIN_ENDPOINT, 'GET', True),
    (LOGIN_ENDPOINT, 'DELETE', False),
    (RUN_AS_LOGIN_ENDPOINT, 'DELETE', False),
    ('/agents', 'POST', False),
    ('/agents', 'GET', False),
    ('/agents', 'DELETE', False),
])
async def test_check_block_ip_middleware(endpoint, method, call_check, mock_req):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = CheckBlockedIP(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = method
    mock_req.url.path = endpoint
    mock_req.method = method

    with TestContext(operation=operation), \
        patch('api.middlewares.check_blocked_ip') as mock_block_ip:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        if call_check:
            mock_block_ip.assert_called_once_with(mock_req)
        else:
            mock_block_ip.assert_not_called()
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert ret_response == response

@pytest.mark.asyncio
@pytest.mark.parametrize("expect_value", ['test-value', '100-continue'])
async def test_check_expect_header_middleware(expect_value):
    """Test expect header."""
    middleware = CheckExpectHeaderMiddleware(AsyncApp(__name__))

    mock_request = MagicMock(headers={'Expect': expect_value})

    response = Response("Success")

    call_next_mock = AsyncMock(return_value=response)

    if expect_value != '100-continue':
        with pytest.raises(ExpectFailedException):
            await middleware.dispatch(mock_request, call_next_mock)
        call_next_mock.assert_not_called()
    else:
        returned_response = await middleware.dispatch(mock_request, call_next_mock)
        call_next_mock.assert_called_once_with(mock_request)
        assert returned_response == response

@pytest.mark.asyncio
async def test_check_expect_header_middleware_uses_runtime_max_upload_size():
    """Check Expect header uses current api configuration upload size limit."""
    middleware = CheckExpectHeaderMiddleware(AsyncApp(__name__))

    mock_request = MagicMock(headers={
        'Expect': '100-continue',
        'Content-Length': '10'
    })

    call_next_mock = AsyncMock(return_value=Response("Success"))

    with patch('api.middlewares.configuration.api_conf', new={'max_upload_size': 5}):
        with pytest.raises(PayloadTooLargeException) as exc_info:
            await middleware.dispatch(mock_request, call_next_mock)

    call_next_mock.assert_not_called()
    # The expectation is understood; it is the body it announces that is refused, so this is a 413
    # like every other size ceiling in the API, not the 417 an unmeetable expectation gets.
    assert exc_info.value.status == 413
    assert "Maximum content size limit (5) exceeded" in exc_info.value.detail


@pytest.mark.asyncio
async def test_check_expect_header_middleware_no_limit():
    """A `max_upload_size` of 0 disables the ceiling, so no declared length is refused at the header."""
    middleware = CheckExpectHeaderMiddleware(AsyncApp(__name__))

    mock_request = MagicMock(headers={
        'Expect': '100-continue',
        'Content-Length': str(10 * 1024 * 1024 * 1024)
    })
    response = Response("Success")
    call_next_mock = AsyncMock(return_value=response)

    with patch('api.middlewares.configuration.api_conf', new={'max_upload_size': 0}):
        returned_response = await middleware.dispatch(mock_request, call_next_mock)

    call_next_mock.assert_called_once_with(mock_request)
    assert returned_response == response


@pytest.mark.parametrize('max_upload_size', [0, 10485760])
def test_setup_middlewares_registers_the_ceiling_last(max_upload_size):
    """The size ceiling is the last middleware registered, at BEFORE_VALIDATION, and only when enabled.

    Any BaseHTTPMiddleware registered after it would sit below it and turn its 413 into a 500.
    """
    app = MagicMock()
    api_conf = {'max_upload_size': max_upload_size, 'access': {'max_request_per_minute': 300},
                'cors': {'enabled': False}}

    with patch('api.middlewares.configuration.api_conf', new=api_conf):
        setup_middlewares(app)

    calls = app.add_middleware.call_args_list
    registered = [c.args[0] for c in calls]

    # Every middleware sits at the exact position the fix depends on. Moving any of the readers
    # (validation-level or below) above the ceiling, or the ceiling itself off BEFORE_VALIDATION,
    # is the regression this guards; asserting presence alone would not catch it.
    assert call(CheckRateLimitsMiddleware, MiddlewarePosition.BEFORE_SECURITY) in calls
    assert call(CheckExpectHeaderMiddleware, MiddlewarePosition.BEFORE_VALIDATION) in calls
    assert call(CheckBlockedIP, MiddlewarePosition.BEFORE_SECURITY) in calls
    assert call(CheckAuthContextSizeMiddleware, MiddlewarePosition.BEFORE_SECURITY) in calls
    assert call(WazuhAccessLoggerMiddleware, MiddlewarePosition.BEFORE_EXCEPTION) in calls
    assert call(SecureHeadersMiddleware, MiddlewarePosition.BEFORE_EXCEPTION) in calls

    if max_upload_size:
        # The ceiling is strictly the last middleware registered, so no BaseHTTPMiddleware can end
        # up beneath it and turn its ContentSizeExceeded into a 500.
        assert registered[-1] is ContentSizeLimitMiddleware
        assert calls[-1] == call(ContentSizeLimitMiddleware, MiddlewarePosition.BEFORE_VALIDATION,
                                 max_content_size=max_upload_size)
        assert ContentSizeLimitMiddleware not in registered[:-1]
    else:
        assert ContentSizeLimitMiddleware not in registered


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize("username_with_special_chars", [
    'user\nname',
    'user\r\nname',
    'user\tname',
    'multi\n\r\tline',
    'normal_user',
])
async def test_access_log_forwards_raw_username_basic_auth(username_with_special_chars, mock_req):
    """Test that access_log forwards the Basic auth username untouched: custom_logging escapes it."""
    response = MagicMock()
    response.status_code = 401

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {}
    mock_req.method = 'GET'
    mock_req.context = {}
    mock_req.scope = {'path': LOGIN_ENDPOINT}
    mock_req.headers = {'content-type': 'None'}

    encoded_creds = f'{username_with_special_chars}:password'
    sec_header = ('basic', encoded_creds)

    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('api.middlewares.base64.b64decode', return_value=encoded_creds.encode("latin1")), \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header):
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)

        mock_custom_logging.assert_called_once()
        logged_username = mock_custom_logging.call_args[0][0]
        assert logged_username == username_with_special_chars


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize("username_with_special_chars", [
    'user\nname',
    'user\r\nname',
    'user\tname',
])
async def test_access_log_forwards_raw_username_jwt(username_with_special_chars, mock_req):
    """Test that access_log forwards the JWT username untouched: custom_logging escapes it."""
    response = MagicMock()
    response.status_code = 200

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {}
    mock_req.method = 'GET'
    mock_req.context = {}
    mock_req.scope = {'path': '/agents'}
    mock_req.headers = {'content-type': 'None'}

    sec_header = ('bearer', {'sub': username_with_special_chars})

    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('api.middlewares.jwt.decode', return_value=sec_header[1]), \
        patch('api.middlewares.generate_keypair', return_value=(None, None)), \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header):
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)

        mock_custom_logging.assert_called_once()
        logged_username = mock_custom_logging.call_args[0][0]
        assert logged_username == username_with_special_chars


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize("username_with_special_chars", [
    'user\nname',
    'user\r\nname',
    'user\tname',
    'user\x1b[2Jname',
])
async def test_access_log_warns_on_control_characters(username_with_special_chars, mock_req):
    """Test that access_log logs a one-line warning when usernames contain control characters."""
    response = MagicMock()
    response.status_code = 200

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {}
    mock_req.method = 'GET'
    mock_req.context = {}
    mock_req.scope = {'path': '/agents\nforged'}
    mock_req.headers = {'content-type': 'None'}

    encoded_creds = f'{username_with_special_chars}:password'
    sec_header = ('basic', encoded_creds)

    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging'), \
        patch('api.middlewares.base64.b64decode', return_value=encoded_creds.encode("latin1")), \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header), \
        patch('api.middlewares.logger.warning') as mock_warning:
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)

        mock_warning.assert_called_once()
        warning_message = mock_warning.call_args[0][0]
        assert 'Username contains control characters' in warning_message
        assert 'Path: /agents\\nforged.' in warning_message
        assert '\n' not in warning_message


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_no_warning_for_normal_username(mock_req):
    """Test that access_log does not log a warning for normal usernames without control characters."""
    response = MagicMock()
    response.status_code = 200

    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {}
    mock_req.method = 'GET'
    mock_req.context = {}
    mock_req.scope = {'path': '/agents'}
    mock_req.headers = {'content-type': 'None'}

    encoded_creds = 'normal_user:password'
    sec_header = ('basic', encoded_creds)

    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging'), \
        patch('api.middlewares.base64.b64decode', return_value=encoded_creds.encode("latin1")), \
        patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header), \
        patch('api.middlewares.logger.warning') as mock_warning:
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)

        mock_warning.assert_not_called()


def default_auth_context_limit():
    """Pin the live auth context limit to its default, so the host's installed api.yaml can't skew the test."""
    return patch.dict('api.middlewares.configuration.api_conf',
                      {'auth_context_max_payload_size': AUTH_CONTEXT_MAX_PAYLOAD_SIZE})


def build_ad_ldap_payload(group_count):
    """Build an AD/LDAP-shaped run_as authentication context with `group_count` group entries.

    Parameters
    ----------
    group_count : int
        Number of group entries in the context.

    Returns
    -------
    bytes
        Serialised authentication context.
    """
    auth_context = {
        'auth_context': {
            'user': 'jdoe@example.com',
            'department': 'Security Operations',
            'groups': [
                {
                    'name': f'CN=WazuhGroup{i:04d},OU=Groups,DC=example,DC=com',
                    'sid': f'S-1-5-21-1234567890-987654321-1122334455-{10000 + i}',
                }
                for i in range(group_count)
            ],
        }
    }
    return json.dumps(auth_context).encode()


@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_honours_the_configured_limit():
    """Check that the live `auth_context_max_payload_size` governs, not the module default."""
    custom_limit = 2048
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, content_length=custom_limit + 1)
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch.dict('api.middlewares.configuration.api_conf',
                    {'auth_context_max_payload_size': custom_limit}), \
         pytest.raises(PayloadTooLargeException) as exc_info:
        await middleware.dispatch(request=request, call_next=dispatch_mock)

    assert exc_info.value.status == 413
    assert str(custom_limit) in exc_info.value.detail
    dispatch_mock.assert_not_awaited()

    # The same declared length is below the default limit, so it goes through untouched.
    with default_auth_context_limit():
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response


@pytest.mark.asyncio
async def test_check_auth_context_size_middleware_admits_an_ad_ldap_context():
    """Check that an AD/LDAP context larger than the logging limit is not refused."""
    body = build_ad_ldap_payload(200)
    assert MAX_LOGGED_BODY_SIZE < len(body) < AUTH_CONTEXT_MAX_PAYLOAD_SIZE
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, content_length=len(body))
    middleware = CheckAuthContextSizeMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with default_auth_context_limit():
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_caches_an_auth_context_over_the_logging_limit():
    """Check that the run_as path is bounded by the auth context limit, not by the logging one.

    `CheckAuthContextSizeMiddleware` admits a context up to `auth_context_max_payload_size`, and a
    body this layer does not cache reaches `access_log` with nothing to hash: the attempt would be
    logged without its auth context hash.
    """
    body = build_ad_ldap_payload(120)
    assert MAX_LOGGED_BODY_SIZE < len(body) < AUTH_CONTEXT_MAX_PAYLOAD_SIZE
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, content_length=len(body),
                            receive=chunked_receive(body, 1))
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request), \
         default_auth_context_limit():
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    assert request._body == body


@pytest.mark.asyncio
async def test_wazuh_access_logger_middleware_respects_the_configured_auth_context_limit():
    """Check that lowering the option also lowers what this layer is willing to buffer."""
    custom_limit = 2048
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)
    # `build_request` fails the read, so caching anything at all shows up as an error.
    request = build_request(path=RUN_AS_LOGIN_ENDPOINT, content_length=custom_limit + 1)
    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)

    with patch('api.middlewares.access_log'), \
         patch('api.middlewares.ConnexionRequest.from_starlette_request', return_value=request), \
         patch.dict('api.middlewares.configuration.api_conf',
                    {'auth_context_max_payload_size': custom_limit}):
        assert await middleware.dispatch(request=request, call_next=dispatch_mock) == response

    assert not hasattr(request, '_body')


@pytest.mark.parametrize('debug_enabled, expected_body', [
    (False, {'auth_context': AUTH_CONTEXT_NOT_LOGGED}),
    (True, {'auth_context': {'user': 'jdoe@example.com'}}),
])
@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_access_log_masks_the_auth_context(debug_enabled, expected_body, mock_req):
    """Check that an accepted authorization context reaches api.log only at debug level.

    The context carries third-party identity (AD/LDAP group memberships, SSO claims) and is written
    verbatim to api.log and again to api.json; the hash identifies it without disclosing it.
    """
    auth_context = {'auth_context': {'user': 'jdoe@example.com'}}
    response = MagicMock()
    response.status_code = 200
    mock_req._body = json.dumps(auth_context).encode()
    mock_req.json = AsyncMock(return_value=auth_context)
    mock_req.query_params = {}
    mock_req.method = 'POST'
    mock_req.context = {'user': 'wazuh'}
    mock_req.scope = {'path': RUN_AS_LOGIN_ENDPOINT}
    mock_req.headers = {'content-type': 'application/json'}
    expected_hash = hashlib.blake2b(json.dumps(auth_context).encode(), digest_size=16).hexdigest()

    with patch('api.middlewares.custom_logging') as mock_custom_logging, \
         patch('api.middlewares.logger') as mock_logger, \
         patch('api.middlewares.AbstractSecurityHandler.get_auth_header_value',
               side_effect=OAuthProblem):
        mock_logger.isEnabledFor.return_value = debug_enabled
        await access_log(request=mock_req, response=response,
                         prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

    assert mock_custom_logging.call_args.args[5] == expected_body
    # Substituting the body must not change the digest the issued token carries.
    assert mock_custom_logging.call_args.kwargs['hash_auth_context'] == expected_hash
