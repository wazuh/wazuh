# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import binascii
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, call, patch

import jwt
import pytest
from connexion import AsyncApp
from connexion.exceptions import OAuthProblem, ProblemException
from connexion.testing import TestContext
from freezegun import freeze_time
from starlette.responses import Response
from wazuh.core.authentication import JWT_ALGORITHM
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin

from server_management_api.api_exception import ExpectFailedException
from server_management_api.controllers.test.utils import get_default_configuration
from server_management_api.middlewares import (
    LOGIN_ENDPOINT,
    MAX_REQUESTS_EVENTS_DEFAULT,
    RUN_AS_LOGIN_ENDPOINT,
    UNKNOWN_USER_STRING,
    CheckBlockedIP,
    CheckExpectHeaderMiddleware,
    CheckRateLimitsMiddleware,
    SecureHeadersMiddleware,
    WazuhAccessLoggerMiddleware,
    access_log,
    check_blocked_ip,
    check_rate_limit,
    secure_headers,
)

with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
    default_config = get_default_configuration()
    CentralizedConfig._config = default_config


@pytest.fixture
def request_info(request):
    """Return the dictionary of the parametrize."""
    return request.param if 'prevent_bruteforce_attack' in request.node.name else None


@pytest.fixture
def mock_req(request, request_info):
    """Fixture to wrap functions with request."""
    req = MagicMock()
    req.client.host = 'ip'
    if 'prevent_bruteforce_attack' in request.node.name:
        for clave, valor in request_info.items():
            setattr(req, clave, valor)
    req.json = AsyncMock(side_effect=lambda: {'ctx': ''})
    req.context = MagicMock()
    req.context.get = MagicMock(return_value={})

    return req


@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_check_blocked_ip(mock_req):
    """Test check_blocked_ip function.
    Check if the ip_block is emptied when the blocking period has finished.
    """
    with (
        patch('server_management_api.middlewares.ip_stats', new={'ip': {'timestamp': -300}}) as mock_ip_stats,
        patch('server_management_api.middlewares.ip_block', new={'ip'}) as mock_ip_block,
    ):
        check_blocked_ip(mock_req)
        # Assert that under these conditions, they have been emptied
        assert not mock_ip_stats and not mock_ip_block


@patch('server_management_api.middlewares.ip_stats', new={'ip': {'timestamp': 5}})
@patch('server_management_api.middlewares.ip_block', new={'ip'})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_check_blocked_ip_ko(mock_req):
    """Test if `check_blocked_ip` raises an exception if the IP is still blocked."""
    with (
        pytest.raises(ProblemException) as exc_info,
        patch('server_management_api.middlewares.ConnexionRequest.from_starlette_request', returns_value=mock_req),
    ):
        check_blocked_ip(mock_req)
        assert exc_info.value.status == 403
        assert exc_info.value.title == 'Permission Denied'
        assert exc_info.value.detail == (
            'Limit of login attempts reached. The current IP has been blocked due to a high number of login attempts'
        )
        assert exc_info.ext == mock_req


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize(
    'current_time,max_requests,current_time_key, current_counter_key,expected_error_code',
    [
        (-80, 300, 'events_current_time', 'events_request_counter', 0),
        (-80, 300, 'general_current_time', 'general_request_counter', 0),
        (0, 0, 'events_current_time', 'events_request_counter', 6005),
        (0, 0, 'general_current_time', 'general_request_counter', 6001),
    ],
)
def test_middlewares_check_rate_limit(
    current_time, max_requests, current_time_key, current_counter_key, expected_error_code, mock_req
):
    """Test if the rate limit mechanism triggers when the `max_requests` are reached."""
    with patch(f'server_management_api.middlewares.{current_time_key}', new=current_time):
        code = check_rate_limit(
            current_time_key=current_time_key,
            request_counter_key=current_counter_key,
            max_requests=max_requests,
            error_code=expected_error_code,
        )
        assert code == expected_error_code


@pytest.mark.asyncio
@pytest.mark.parametrize('endpoint', ['/agents', '/events'])
async def test_check_rate_limits_middleware(endpoint, mock_req):
    """Test limits middleware."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name='operation')
    operation.method = 'post'
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    rq_x_min = 10000
    default_config.management_api.access.max_request_per_minute = rq_x_min
    with (
        TestContext(operation=operation),
        patch('server_management_api.middlewares.check_rate_limit', return_value=0) as mock_check,
    ):
        await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        if endpoint == '/events':
            mock_check.assert_has_calls(
                [
                    call('general_request_counter', 'general_current_time', rq_x_min, 6001),
                    call('events_request_counter', 'events_current_time', MAX_REQUESTS_EVENTS_DEFAULT, 6005),
                ],
                any_order=False,
            )
        else:
            mock_check.assert_called_once_with('general_request_counter', 'general_current_time', rq_x_min, 6001)
        dispatch_mock.assert_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'endpoint, return_code_general, return_code_events',
    [
        ('/agents', 6001, 0),
        ('/events', 0, 6005),
        ('/events', 6001, 6005),
    ],
)
async def test_check_rate_limits_middleware_ko(endpoint, return_code_general, return_code_events, mock_req):
    """Test limits middleware."""
    return_value_sequence = [return_code_general, return_code_events]

    def check_rate_limit_side_effect(*_):
        """Side effect function."""
        return return_value_sequence.pop(0)

    dispatch_mock = AsyncMock()
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name='operation')
    operation.method = 'post'
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    rq_x_min = 10000
    with (
        TestContext(operation=operation),
        patch(
            'server_management_api.middlewares.ConnexionRequest.from_starlette_request', return_value=mock_req
        ) as mock_from,
        patch('server_management_api.middlewares.check_rate_limit', side_effect=check_rate_limit_side_effect),
        pytest.raises(ProblemException) as exc_info,
    ):
        await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_from.assert_called_once_with(mock_req)
        dispatch_mock.assert_not_awaited()
        assert exc_info.value.status == 429
        assert exc_info.value.title == 'Permission Denied'
        assert exc_info.value.detail == return_code_general if endpoint == 'event' else return_code_events
        assert exc_info.ext == mock_req


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize(
    'json_body, q_password, b_password, b_key, c_user, hash, sec_header, endpoint, method, status_code',
    [
        (True, None, None, None, None, 'hash', ('basic', 'wazuh:pwd'), '/agents', 'GET', 200),
        (False, 'q_pass', 'b_pass', 'b_key', 'wazuh', '', ('basic', 'wazuh:pwd'), LOGIN_ENDPOINT, 'GET', 200),
        (False, None, 'b_pass', 'b_key', 'wazuh', '', ('bearer', {'sub': 'wazuh'}), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
        (False, 'q_pass', None, 'b_key', 'wazuh', '', ('bearer', {'sub': 'wazuh'}), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
        (False, 'q_pass', None, 'b_key', 'wazuh', '', ('other', ''), RUN_AS_LOGIN_ENDPOINT, 'POST', 403),
    ],
)
async def test_access_log(
    json_body, q_password, b_password, b_key, c_user, hash, sec_header, endpoint, method, status_code, mock_req
):
    """Test access_log function."""
    response = MagicMock()
    response.status_code = status_code

    operation = MagicMock(name='operation')
    operation.method = 'post'

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
    mock_blacke2b.return_value.hexdigest.return_value = f'blackeb2 {hash}'
    with (
        TestContext(operation=operation),
        patch('server_management_api.middlewares.custom_logging') as mock_custom_logging,
        patch('hashlib.blake2b', mock_blacke2b),
        patch(
            'server_management_api.middlewares.base64.b64decode',
            return_value=sec_header[1].encode('latin1') if isinstance(sec_header[1], str) else '',
        ) as mock_b64decode,
        patch('server_management_api.middlewares.jwt.decode', return_value=sec_header[1]) as mock_jwt_decode,
        patch('server_management_api.middlewares.get_keypair', return_value=(None, None)) as mock_get_keypair,
        patch('server_management_api.middlewares.logger.warning', return_value=(None, None)) as mock_log_warning,
        patch(
            'server_management_api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header
        ) as mock_get_headers,
    ):
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
                mock_get_keypair.assert_called_once()
                mock_jwt_decode.assert_called_once_with(sec_header[1], None, [JWT_ALGORITHM])

        if not hash and endpoint == RUN_AS_LOGIN_ENDPOINT:
            mock_blacke2b.assert_called_once()
            hash = f'blackeb2 {hash}'
        mock_req.query_params.update({'password': '****'} if q_password else {})
        body.update({'password': '****'} if b_key else {})
        body.update({'key': '****'} if b_key and endpoint == '/agents' else {})
        mock_custom_logging.assert_called_once_with(
            expected_user,
            mock_req.client.host,
            mock_req.method,
            endpoint,
            mock_req.query_params,
            body,
            0.0,
            response.status_code,
            hash_auth_context=hash,
            headers=mock_req.headers,
        )
        if status_code == 403 and endpoint in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and method in {'GET', 'POST'}:
            mock_log_warning.assert_called_once_with(
                f'IP blocked due to exceeded number of logins attempts: {mock_req.client.host}'
            )


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

    with (
        patch('server_management_api.middlewares.custom_logging') as mock_custom_logging,
        patch('server_management_api.middlewares.jwt.decode', return_value=sec_header[1]),
        patch('server_management_api.middlewares.get_keypair', return_value=(None, None)),
        patch(
            'server_management_api.middlewares.AbstractSecurityHandler.get_auth_header_value', return_value=sec_header
        ),
    ):
        await access_log(request=mock_req, response=response, prev_time=datetime(1970, 1, 1, 0, 0, 10).timestamp())

        mock_custom_logging.assert_called_once_with(
            user,
            mock_req.client.host,
            mock_req.method,
            endpoint,
            mock_req.query_params,
            body,
            0.0,
            response.status_code,
            hash_auth_context=hash_auth_context,
            headers=mock_req.headers,
        )


@freeze_time(datetime(1970, 1, 1, 0, 0, 0))
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'exception', [(OAuthProblem), (jwt.exceptions.PyJWTError), (KeyError), (IndexError), (binascii.Error)]
)
async def test_access_log_ko(mock_req, exception):
    """Test access_log authorization header decoding exceptions."""
    user = UNKNOWN_USER_STRING
    endpoint = LOGIN_ENDPOINT
    method = 'GET'
    status_code = 401

    response = MagicMock()
    response.status_code = status_code

    operation = MagicMock(name='operation')
    operation.method = 'post'

    body = {}
    mock_req.json = AsyncMock(return_value=body)
    mock_req.query_params = {'password': '****'}
    mock_req.method = method
    mock_req.context.update({'user': user})
    mock_req.scope = {'path': endpoint}
    mock_req.headers = {'content-type': 'None'}

    with (
        TestContext(operation=operation),
        patch('server_management_api.middlewares.custom_logging') as mock_custom_logging,
        patch('server_management_api.middlewares.AbstractSecurityHandler.get_auth_header_value', side_effect=exception),
    ):
        expected_time = datetime(1970, 1, 1, 0, 0, 0).timestamp()
        await access_log(request=mock_req, response=response, prev_time=expected_time)
        mock_custom_logging.assert_called_once_with(
            user,
            mock_req.client.host,
            mock_req.method,
            endpoint,
            mock_req.query_params,
            body,
            0.0,
            response.status_code,
            hash_auth_context='',
            headers=mock_req.headers,
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
    operation = MagicMock(name='operation')
    operation.method = 'post'

    with (
        TestContext(operation=operation),
        patch('server_management_api.middlewares.access_log') as mock_access_log,
        patch(
            'server_management_api.middlewares.ConnexionRequest.from_starlette_request', return_value=mock_req
        ) as mock_from,
    ):
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
        resp = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_from.assert_called_once_with(mock_req)
        mock_access_log.assert_called_once_with(mock_req, response, expected_time)
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert resp == response


@pytest.mark.asyncio
async def test_secure_headers_middleware(mock_req):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = SecureHeadersMiddleware(AsyncApp(__name__))
    operation = MagicMock(name='operation')
    operation.method = 'post'

    with TestContext(operation=operation), patch('server_management_api.middlewares.secure_headers') as mock_secure:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_secure.framework.starlette.assert_called_once_with(response)
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert ret_response == response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'endpoint, method, call_check',
    [
        (LOGIN_ENDPOINT, 'POST', True),
        (RUN_AS_LOGIN_ENDPOINT, 'POST', True),
        (LOGIN_ENDPOINT, 'GET', True),
        (RUN_AS_LOGIN_ENDPOINT, 'GET', True),
        (LOGIN_ENDPOINT, 'DELETE', False),
        (RUN_AS_LOGIN_ENDPOINT, 'DELETE', False),
        ('/agents', 'POST', False),
        ('/agents', 'GET', False),
        ('/agents', 'DELETE', False),
    ],
)
async def test_check_block_ip_middleware(endpoint, method, call_check, mock_req):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = CheckBlockedIP(AsyncApp(__name__))
    operation = MagicMock(name='operation')
    operation.method = method
    mock_req.url.path = endpoint
    mock_req.method = method

    with TestContext(operation=operation), patch('server_management_api.middlewares.check_blocked_ip') as mock_block_ip:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        if call_check:
            mock_block_ip.assert_called_once_with(mock_req)
        else:
            mock_block_ip.assert_not_called()
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert ret_response == response


@pytest.mark.asyncio
@pytest.mark.parametrize('expect_value', ['test-value', '100-continue'])
async def test_check_expect_header_middleware(expect_value):
    """Test expect header."""
    middleware = CheckExpectHeaderMiddleware(AsyncApp(__name__))

    mock_request = MagicMock(headers={'Expect': expect_value})

    response = Response('Success')

    call_next_mock = AsyncMock(return_value=response)

    if expect_value != '100-continue':
        with pytest.raises(ExpectFailedException):
            await middleware.dispatch(mock_request, call_next_mock)
        call_next_mock.assert_not_called()
    else:
        returned_response = await middleware.dispatch(mock_request, call_next_mock)
        call_next_mock.assert_called_once_with(mock_request)
        assert returned_response == response
