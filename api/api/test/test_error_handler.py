# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from freezegun import freeze_time

from connexion.exceptions import HTTPException, ProblemException, Unauthorized
from connexion.lifecycle import ConnexionRequest
from api.error_handler import _cleanup_detail_field, \
    http_error_handler, problem_error_handler, unauthorized_error_handler, \
    expect_failed_error_handler, recursion_error_handler, ERROR_CONTENT_TYPE
from api.middlewares import LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT, general_request_stats
from api.api_exception import ExpectFailedException


@pytest.fixture
def mock_request():
    """fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    req.query_param = {}

    return req


@pytest.fixture(autouse=True)
def clean_rate_limit_state():
    """Keep the rate limiters' module level buckets from leaking between tests."""
    general_request_stats.clear()
    yield
    general_request_stats.clear()


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing

    Details field.
    """

    assert _cleanup_detail_field(detail) == "Testing. Details field."


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.parametrize('path, method, token_info', [
    (LOGIN_ENDPOINT, 'GET', True),
    (LOGIN_ENDPOINT, 'POST', False),
    (RUN_AS_LOGIN_ENDPOINT, 'POST', True),
    ('/agents', 'POST', False),
])
async def test_unauthorized_error_handler(path, method, token_info, mock_request):
    """Test unauthorized error handler."""
    problem = {
        "title": "Unauthorized",
    }
    detail = 'test'
    exc = Unauthorized(detail)
    mock_request.configure_mock(scope={'path': path})
    mock_request.method = method
    if path in {LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT} \
        and method in {'GET', 'POST'}:
        problem['detail'] = "Invalid credentials"
    else:
        if token_info:
            mock_request.context = {'token_info': ''}
        else:
            problem['detail'] = detail
            mock_request.context = {}

    response = await unauthorized_error_handler(mock_request, exc)
    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == exc.status_code
    assert response.content_type == ERROR_CONTENT_TYPE


@pytest.mark.asyncio
@pytest.mark.parametrize('detail', [None, 'Custom detail'])
async def test_http_error_handler(detail, mock_request):
    """Test http error handler."""
    exc = HTTPException(status_code=401, detail=detail)
    problem = {
        "title": exc.detail,
        'detail': f"{exc.status_code}: {exc.detail}"
    }
    response = await http_error_handler(mock_request, exc)

    body = json.loads(response.body)
    assert body == problem
    assert response.status_code == 401
    assert response.content_type == ERROR_CONTENT_TYPE


@pytest.mark.asyncio
@pytest.mark.parametrize('status_code, reason', [(404, 'Not Found'), (405, 'Method Not Allowed')])
@pytest.mark.parametrize('path', ['/nope', LOGIN_ENDPOINT, RUN_AS_LOGIN_ENDPOINT])
@pytest.mark.parametrize('headers', [{}, {'Authorization': 'Basic dXNlcjpwYXNz'}, {'Authorization': 'Bearer'}])
async def test_http_error_handler_no_token(headers, path, status_code, reason, mock_request):
    """Test that a 404 or 405 without a bearer token is answered with the 401 of a protected route."""
    mock_request.configure_mock(scope={'path': path}, headers=headers)
    mock_request.method = 'GET'
    with patch('api.error_handler.decode_token', new=AsyncMock()) as decode_mock:
        response = await http_error_handler(mock_request, HTTPException(status_code=status_code, detail=reason))

    decode_mock.assert_not_awaited()
    assert response.status_code == 401
    assert response.content_type == ERROR_CONTENT_TYPE
    body = json.loads(response.body)
    assert body['title'] == 'Unauthorized'
    assert body['detail'] == ('Invalid authorization header' if headers.get('Authorization') == 'Bearer'
                              else 'No authorization token provided')


@pytest.mark.asyncio
@pytest.mark.parametrize('status_code, reason', [(404, 'Not Found'), (405, 'Method Not Allowed')])
@pytest.mark.parametrize('detail', ['Invalid token', 'Token expired'])
async def test_http_error_handler_rejected_token(detail, status_code, reason, mock_request):
    """Test that a 404 or 405 with a bearer token `decode_token` rejects is answered with its 401."""
    mock_request.headers = {'Authorization': 'Bearer token'}
    with patch('api.error_handler.decode_token', new=AsyncMock(side_effect=Unauthorized(detail))) as decode_mock:
        response = await http_error_handler(mock_request, HTTPException(status_code=status_code, detail=reason))

    decode_mock.assert_awaited_once_with('token')
    assert response.status_code == 401
    assert json.loads(response.body) == {'title': 'Unauthorized', 'detail': detail}


@pytest.mark.asyncio
@pytest.mark.parametrize('status_code, reason', [(404, 'Not Found'), (405, 'Method Not Allowed')])
async def test_http_error_handler_valid_token(status_code, reason, mock_request):
    """Test that a 404 or 405 with a valid bearer token keeps its original answer."""
    mock_request.headers = {'Authorization': 'bearer token'}
    with patch('api.error_handler.decode_token', new=AsyncMock(return_value={})) as decode_mock:
        response = await http_error_handler(mock_request, HTTPException(status_code=status_code, detail=reason))

    decode_mock.assert_awaited_once_with('token')
    assert response.status_code == status_code
    assert json.loads(response.body) == {'title': reason, 'detail': f"{status_code}: {reason}"}


@pytest.mark.asyncio
@pytest.mark.parametrize('status_code, reason, max_request, charged', [
    (405, 'Method Not Allowed', 300, True),
    (405, 'Method Not Allowed', 0, True),
    (404, 'Not Found', 0, True),
    # CheckAuthenticatedRateLimitMiddleware has already charged it
    (404, 'Not Found', 300, False),
])
@pytest.mark.parametrize('authorization', [None, 'Bearer token'], ids=['no-token', 'valid-token'])
async def test_http_error_handler_charges_the_unauthenticated_bucket(authorization, status_code, reason,
                                                                    max_request, charged, mock_request):
    """Test that a 404 or 405 no rate-limit middleware charged is charged here, before the token is checked."""
    mock_request.headers = {'Authorization': authorization} if authorization else {}
    api_conf = {'access': {'max_request_per_minute': max_request, 'max_unauthenticated_request_per_minute': 2}}
    answers = []

    with patch('api.error_handler.configuration.api_conf', new=api_conf), \
         patch('api.error_handler.decode_token', new=AsyncMock(return_value={})) as decode_mock:
        for _ in range(3):
            response = await http_error_handler(mock_request, HTTPException(status_code=status_code, detail=reason))
            answers.append(response.status_code)

    answer = status_code if authorization else 401
    if charged:
        assert answers == [answer, answer, 429]
        assert json.loads(response.body)['error'] == 6005
        # The refused request never reaches the token check
        assert decode_mock.await_count == (2 if authorization else 0)
    else:
        assert answers == [answer] * 3


@pytest.mark.asyncio
async def test_http_error_handler_unlimited_unauthenticated_bucket(mock_request):
    """Test that `max_unauthenticated_request_per_minute: 0` never refuses a 405."""
    mock_request.headers = {}
    api_conf = {'access': {'max_request_per_minute': 300, 'max_unauthenticated_request_per_minute': 0}}

    with patch('api.error_handler.configuration.api_conf', new=api_conf):
        answers = [(await http_error_handler(mock_request, HTTPException(status_code=405, detail='x'))).status_code
                   for _ in range(25)]

    assert answers == [401] * 25


@pytest.mark.asyncio
@pytest.mark.parametrize('status_code, reason', [(403, 'Forbidden'), (429, 'Too Many Requests')])
async def test_http_error_handler_other_status_not_authenticated(status_code, reason, mock_request):
    """Test that a status other than 404 and 405 is answered without checking the token."""
    mock_request.headers = {}
    with patch('api.error_handler.decode_token', new=AsyncMock()) as decode_mock:
        response = await http_error_handler(mock_request, HTTPException(status_code=status_code, detail=reason))

    decode_mock.assert_not_awaited()
    assert response.status_code == status_code
    assert json.loads(response.body) == {'title': reason, 'detail': f"{status_code}: {reason}"}


@pytest.mark.asyncio
@pytest.mark.parametrize('title, detail, ext, error_type', [
                          ('title', 'detail \n detail\n', {}, None),
                          ('', 'detail', {}, None),
                          ('', '', {}, None),
                          ('', 'detail', {'status': 'status'}, None),
                          ('', 'detail', {'type': 'type'}, None),
                          ('', 'detail', {'code': 3005}, None),
                          ('', 'detail', {'code': 3005}, None),
                          ('', 'detail', {'code': 3005}, 'type'),
                          ('', {'detail_1':'detail_1'}, {'code': 3005}, 'type'),
                          ('', {}, {'code': 3005}, 'type'),
                          ('', {}, {'status': 'status'}, 'type'),
                          ('', {}, {'type': 'type'}, 'type'),
                          ('', {}, {'type': 'type', 'more': 'more'}, 'type'),
])
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
@pytest.mark.parametrize('query_param_pretty, expected_detail', [
    ('true', "Unknown Expect"),
    ('false', "Unknown Expect"),
])
async def test_expect_failed_error_handler(query_param_pretty, expected_detail):
    """Test expect failed error handler."""
    request = MagicMock()
    request.query_params = {'pretty': query_param_pretty}
    response = await expect_failed_error_handler(request, ExpectFailedException(detail=expected_detail) if expected_detail else None)
    
    assert response.status_code == 417
    assert response.content_type == ERROR_CONTENT_TYPE
    
    body = json.loads(response.body)
    assert body["title"] == "Expectation failed"
    if expected_detail:
        assert body["detail"] == expected_detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query_params, expected_pretty",
    [
        ({"pretty": "true"}, True),
        ({"pretty": "false"}, False),
        ({}, False),
        ({"pretty": "TRUE"}, False),  # case-sensitive
        ({"pretty": "1"}, False),     # valores no válidos
    ],
)
@patch("api.error_handler.build_recursion_error_response")
async def test_recursion_error_handler_pretty(mock_build, query_params, expected_pretty):
    """Test recursion_error_handler pretty param handling."""

    request = MagicMock(spec=ConnexionRequest)
    request.query_params = query_params

    expected_response = MagicMock()
    mock_build.return_value = expected_response

    exc = RecursionError()

    result = await recursion_error_handler(request, exc)

    mock_build.assert_called_once_with(pretty=expected_pretty)
    assert result == expected_response
