# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from copy import copy
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from connexion.exceptions import HTTPException, ProblemException, Unauthorized
from freezegun import freeze_time

from api.api_exception import ExpectFailedException
from api.error_handler import (
    ERROR_CONTENT_TYPE,
    _cleanup_detail_field,
    expect_failed_error_handler,
    http_error_handler,
    prevent_bruteforce_attack,
    problem_error_handler,
    unauthorized_error_handler,
)
from api.middlewares import LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT


@pytest.fixture
def request_info(request):
    """Return the dictionary of the parametrize"""
    return request.param if 'prevent_bruteforce_attack' in request.node.name else None


@pytest.fixture
def mock_request(request, request_info):
    """Fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    mock_request.query_param = {}
    if 'prevent_bruteforce_attack' in request.node.name:
        for clave, valor in request_info.items():
            setattr(req, clave, valor)

    return req


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing

    Details field.
    """

    assert _cleanup_detail_field(detail) == 'Testing. Details field.'


@pytest.mark.parametrize(
    'stats',
    [
        {},
        {'ip': {'attempts': 4}},
    ],
)
@pytest.mark.parametrize(
    'request_info',
    [
        {'path': LOGIN_ENDPOINT, 'method': 'GET', 'pretty': 'true'},
        {'path': LOGIN_ENDPOINT, 'method': 'POST', 'pretty': 'false'},
        {'path': RUN_AS_LOGIN_ENDPOINT, 'method': 'POST'},
    ],
    indirect=True,
)
def test_middlewares_prevent_bruteforce_attack(stats, request_info, mock_request):
    """Test `prevent_bruteforce_attack` blocks IPs when reaching max number of attempts."""
    mock_request.configure_mock(scope={'path': request_info['path']})
    mock_request.method = request_info['method']
    mock_request.query_param['pretty'] = request_info.get('pretty', 'false')
    with (
        patch('api.error_handler.ip_stats', new=copy(stats)) as ip_stats,
        patch('api.error_handler.ip_block', new=set()) as ip_block,
    ):
        previous_attempts = ip_stats['ip']['attempts'] if 'ip' in ip_stats else 0
        prevent_bruteforce_attack(mock_request, attempts=5)
        if stats:
            # There were previous attempts. This one reached the limit
            assert ip_stats['ip']['attempts'] == previous_attempts + 1
            assert 'ip' in ip_block
        else:
            # There were not previous attempts
            assert ip_stats['ip']['attempts'] == 1
            assert 'ip' not in ip_block


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize(
    'path, method, token_info',
    [
        (LOGIN_ENDPOINT, 'GET', True),
        (LOGIN_ENDPOINT, 'POST', False),
        (RUN_AS_LOGIN_ENDPOINT, 'POST', True),
        ('/agents', 'POST', False),
    ],
)
async def test_unauthorized_error_handler(path, method, token_info, mock_request):
    """Test unauthorized error handler."""
    problem = {
        'title': 'Unauthorized',
    }
    detail = 'test'
    exc = Unauthorized(detail)
    mock_request.configure_mock(scope={'path': path})
    mock_request.method = method
    if path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and method in {'GET', 'POST'}:
        problem['detail'] = 'Invalid credentials'
    else:
        if token_info:
            mock_request.context = {'token_info': ''}
        else:
            problem['detail'] = detail
            mock_request.context = {}

    with (
        patch('api.error_handler.prevent_bruteforce_attack') as mock_pbfa,
        patch('api.configuration.api_conf', new={'access': {'max_login_attempts': 1000}}),
    ):
        response = await unauthorized_error_handler(mock_request, exc)
        if path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} and method in {'GET', 'POST'}:
            mock_pbfa.assert_called_once_with(request=mock_request, attempts=1000)
        expected_time = datetime(1970, 1, 1, 0, 0, 10).timestamp()
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == exc.status_code
    assert response.content_type == ERROR_CONTENT_TYPE


@pytest.mark.asyncio
@pytest.mark.parametrize('detail', [None, 'Custom detail'])
async def test_http_error_handler(detail, mock_request):
    """Test http error handler."""
    exc = HTTPException(status_code=401, detail=detail)
    problem = {'title': exc.detail, 'detail': f'{exc.status_code}: {exc.detail}'}
    response = await http_error_handler(mock_request, exc)

    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == 401
    assert response.content_type == ERROR_CONTENT_TYPE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'title, detail, ext, error_type',
    [
        ('title', 'detail \n detail\n', {}, None),
        ('', 'detail', {}, None),
        ('', '', {}, None),
        ('', 'detail', {'status': 'status'}, None),
        ('', 'detail', {'type': 'type'}, None),
        ('', 'detail', {'code': 3005}, None),
        ('', 'detail', {'code': 3005}, None),
        ('', 'detail', {'code': 3005}, 'type'),
        ('', {'detail_1': 'detail_1'}, {'code': 3005}, 'type'),
        ('', {}, {'code': 3005}, 'type'),
        ('', {}, {'status': 'status'}, 'type'),
        ('', {}, {'type': 'type'}, 'type'),
        ('', {}, {'type': 'type', 'more': 'more'}, 'type'),
    ],
)
async def test_problem_error_handler(title, detail, ext, error_type, mock_request):
    """Test problem error handler."""
    exc = ProblemException(status=400, title=title, detail=detail, ext=ext, type=error_type)
    response = await problem_error_handler(mock_request, exc)
    body = json.loads(response.body)

    if isinstance(detail, dict):
        if 'type' in detail:
            detail.pop('type')
        if 'status' in detail:
            detail.pop('status')
    elif isinstance(detail, str):
        detail = _cleanup_detail_field(detail)
    problem = {}
    problem.update({'title': title} if title else {'title': 'Bad Request'})
    problem.update({'type': error_type} if (error_type and error_type != 'about:blank') else {})
    problem.update({'detail': detail} if detail else {})
    problem.update(ext if ext else {})
    problem.update({'error': problem.pop('code')} if 'code' in problem else {})

    assert response.status_code == 400
    assert response.content_type == ERROR_CONTENT_TYPE
    assert body == problem


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'query_param_pretty, expected_detail',
    [
        ('true', 'Unknown Expect'),
        ('false', 'Unknown Expect'),
    ],
)
async def test_expect_failed_error_handler(query_param_pretty, expected_detail):
    """Test expect failed error handler."""
    request = MagicMock()
    request.query_params = {'pretty': query_param_pretty}
    response = await expect_failed_error_handler(
        request, ExpectFailedException(detail=expected_detail) if expected_detail else None
    )

    assert response.status_code == 417
    assert response.content_type == ERROR_CONTENT_TYPE

    body = json.loads(response.body)
    assert body['title'] == 'Expectation failed'
    if expected_detail:
        assert body['detail'] == expected_detail
