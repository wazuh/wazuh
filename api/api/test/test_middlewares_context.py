# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Pin the contract that lets `access_log` know whether the caller was authenticated.

`WazuhAccessLoggerMiddleware` sits outside connexion's `RoutingMiddleware`, which passes a shallow
copy of the ASGI scope downwards. The identity the security handler writes into the copy's
`extensions` is therefore only visible to the access logger because the middleware creates
`extensions` before the request is dispatched, which makes the copy share that very dict.

The rest of the suite asserts the decision taken from that context by setting it directly. These
cases assert the mechanism it rests on, against a real connexion application: if an upgrade stopped
routing from shallow-copying the scope, every mocked test would still pass while request bodies
silently stopped being logged.
"""

import asyncio
import hashlib
import json
from unittest.mock import patch

import pytest

from connexion import AsyncApp
from connexion.middleware import MiddlewarePosition

from api.middlewares import (
    CheckAuthContextSizeMiddleware,
    RUN_AS_LOGIN_ENDPOINT,
    WazuhAccessLoggerMiddleware,
)

SPEC = {
    'openapi': '3.0.0',
    'info': {'title': 'context contract', 'version': '1'},
    'components': {'securitySchemes': {'jwt': {
        'type': 'http',
        'scheme': 'bearer',
        'bearerFormat': 'JWT',
        'x-bearerInfoFunc': 'api.test.test_middlewares_context._decode_token',
    }}},
    'security': [{'jwt': []}],
    'paths': {
        '/t': {'post': {
            'operationId': 'api.test.test_middlewares_context._handler',
            'requestBody': {'content': {'application/json': {'schema': {'type': 'object'}}}},
            'responses': {'200': {'description': 'ok'}},
        }},
        RUN_AS_LOGIN_ENDPOINT: {'post': {
            'operationId': 'api.test.test_middlewares_context._run_as_handler',
            'requestBody': {'content': {'application/json': {'schema': {'type': 'object'}}}},
            'responses': {'200': {'description': 'ok'}},
        }},
    },
}

AUTHENTICATED_USER = 'wazuh'


def _decode_token(token):
    """Stand in for the API's bearer handler: accept one token, reject everything else."""
    return {'sub': AUTHENTICATED_USER, 'scope': []} if token == 'good' else None


def _handler(body=None):
    return {'ok': True}, 200


# connexion indexes operations by operationId, so the two paths need distinct ones or the second
# registration replaces the first.
_run_as_handler = _handler


def _build_app():
    app = AsyncApp(__name__)
    app.add_api(SPEC)
    app.add_middleware(CheckAuthContextSizeMiddleware, position=MiddlewarePosition.BEFORE_SECURITY)
    app.add_middleware(WazuhAccessLoggerMiddleware, position=MiddlewarePosition.BEFORE_EXCEPTION)
    return app


async def _start(app):
    """Run the ASGI lifespan so connexion builds its middleware stack."""
    queue = asyncio.Queue()
    await queue.put({'type': 'lifespan.startup'})
    started = asyncio.Event()

    async def receive():
        return await queue.get()

    async def send(message):
        if message['type'].startswith('lifespan.startup'):
            started.set()

    task = asyncio.create_task(app({'type': 'lifespan', 'asgi': {'version': '3.0'}},
                                   receive, send))
    await asyncio.wait_for(started.wait(), 15)
    return task, queue


async def _post(app, token, path='/t', body=None, declare_length=True):
    """Send a JSON body, with or without a bearer token, declaring its length or streaming it."""
    body = json.dumps({'a': 1}).encode() if body is None else body
    chunks = [body[:len(body) // 2], body[len(body) // 2:]] if not declare_length else [body]
    headers = [(b'content-type', b'application/json')]
    if declare_length:
        headers.append((b'content-length', str(len(body)).encode()))
    if token:
        headers.append((b'authorization', f'Bearer {token}'.encode()))

    async def receive():
        return ({'type': 'http.request', 'body': chunks.pop(0), 'more_body': bool(chunks)}
                if chunks else {'type': 'http.disconnect'})

    async def send(message):
        pass

    await app({'type': 'http', 'http_version': '1.1', 'method': 'POST', 'scheme': 'http',
               'server': ('testserver', 80), 'client': ('testclient', 1), 'root_path': '',
               'path': path, 'raw_path': path.encode(), 'query_string': b'', 'headers': headers,
               'asgi': {'version': '3.0', 'spec_version': '2.3'}}, receive, send)


@pytest.mark.parametrize('token, expected_user', [
    ('good', AUTHENTICATED_USER),
    (None, None),
])
@pytest.mark.asyncio
async def test_access_log_reads_the_authenticated_identity(token, expected_user):
    """Check that the identity the security handler settles on reaches `access_log`."""
    contexts = []

    async def spy(request, response, prev_time):
        contexts.append(dict(request.context))

    app = _build_app()
    task, queue = await _start(app)
    try:
        with patch('api.middlewares.access_log', side_effect=spy):
            await _post(app, token)
    finally:
        await queue.put({'type': 'lifespan.shutdown'})
        task.cancel()

    assert len(contexts) == 1
    assert contexts[0].get('user') == expected_user


@pytest.mark.asyncio
async def test_dispatch_creates_the_extensions_scope_key():
    """Check that `extensions` is created before dispatch, which is what makes the copy shared."""
    seen = {}

    async def call_next(request):
        # This is what connexion's RoutingMiddleware does with the scope before security runs.
        seen['inner'] = request.scope.copy()
        raise AssertionError('not reached')

    from starlette.requests import Request

    request = Request({'type': 'http', 'http_version': '1.1', 'method': 'POST', 'scheme': 'http',
                       'server': ('testserver', 80), 'client': ('testclient', 1), 'root_path': '',
                       'path': '/t', 'raw_path': b'/t', 'query_string': b'', 'headers': []},
                      None)
    middleware = WazuhAccessLoggerMiddleware(_build_app())

    with pytest.raises(AssertionError, match='not reached'):
        await middleware.dispatch(request=request, call_next=call_next)

    assert 'extensions' in request.scope
    # The shallow copy shares the dict, so anything written below is visible above.
    assert seen['inner']['extensions'] is request.scope['extensions']


@pytest.mark.parametrize('declare_length', [True, False])
@pytest.mark.asyncio
async def test_access_log_reports_a_run_as_body_however_it_was_read(declare_length):
    """Check that a run_as auth context is logged and hashed whether or not it declares a length.

    A declared length is read by the access logger itself; a chunked body can only be read by
    `CheckAuthContextSizeMiddleware`, which caps it as it arrives. That middleware sits below the
    access logger, and a body cached in one `BaseHTTPMiddleware` request is replayed downwards but
    never upwards, so the bytes have to be handed over through the scope. Without that hand-off the
    chunked attempt reaches the log with an empty body and, worse, with the digest of that empty
    body standing in for the auth context nobody could see.
    """
    auth_context = {'user_name': 'wazuh', 'agent_id': ['001']}
    body = json.dumps(auth_context).encode()
    expected_hash = hashlib.blake2b(json.dumps(auth_context).encode(), digest_size=16).hexdigest()

    app = _build_app()
    task, queue = await _start(app)
    try:
        with patch('api.middlewares.custom_logging') as mock_custom_logging:
            await _post(app, 'good', path=RUN_AS_LOGIN_ENDPOINT, body=body,
                        declare_length=declare_length)
    finally:
        await queue.put({'type': 'lifespan.shutdown'})
        task.cancel()

    mock_custom_logging.assert_called_once()
    assert mock_custom_logging.call_args.args[5] == auth_context
    assert mock_custom_logging.call_args.kwargs['hash_auth_context'] == expected_hash
