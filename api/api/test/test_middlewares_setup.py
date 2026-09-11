# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Tests for the assembled middleware stack, i.e. `api.middlewares.setup_middlewares`.

The order the middlewares end up in is a behavioural contract, not a detail: `ContentSizeLimitMiddleware`
raises `ContentSizeExceeded` from inside an ASGI receive call, and any `BaseHTTPMiddleware` below it
runs that call inside its own anyio task group, where the exception is wrapped in an `ExceptionGroup`
that connexion's exception middleware does not handle -- turning the documented 413 into a 500.
That is exactly how https://github.com/wazuh/wazuh/issues/39127 was introduced, by a middleware added
at the same position as the ceiling and therefore below it, with no test covering the assembled stack.
"""

import re
from unittest.mock import patch

import pytest
from connexion import AsyncApp
from connexion.resolver import Resolver
from content_size_limit_asgi import ContentSizeLimitMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api import middlewares
from api.api_exception import ExpectFailedException
from api.error_handler import content_size_handler, expect_failed_error_handler, problem_error_handler
from api.middlewares import setup_middlewares
from connexion.exceptions import ProblemException
from content_size_limit_asgi.errors import ContentSizeExceeded

MAX_UPLOAD_SIZE = 1024

# Mirrors the two body shapes the real spec has. `/groups` declares a JSON schema, so
# RequestValidationMiddleware reads its body; `/upload` mirrors the configuration uploads
# (`PUT /groups/{group_id}/configuration`, `PUT /cluster/{node_id}/configuration`), whose body
# validation never reads and which are therefore only bounded by the ceiling itself.
SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "test", "version": "1"},
    "paths": {
        "/groups": {
            "post": {
                "operationId": "post_groups",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {"group_id": {"type": "string"}},
                        "required": ["group_id"],
                    }}},
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/upload": {
            "put": {
                "operationId": "put_upload",
                "requestBody": {
                    "required": True,
                    "content": {"application/octet-stream": {"schema": {"type": "string",
                                                                        "format": "binary"}}},
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


def post_groups(body):
    """Handler for the JSON test endpoint."""
    return {"message": "ok"}, 200


def put_upload(body):
    """Handler for the binary test endpoint."""
    return {"length": len(body or b"")}, 200


HANDLERS = {'post_groups': post_groups, 'put_upload': put_upload}


def build_api_conf(max_upload_size: int = MAX_UPLOAD_SIZE, cors: bool = False) -> dict:
    """Build the subset of `api_conf` that `setup_middlewares` reads.

    The rate limit ceilings are deliberately high: these tests are about the shape of the assembled
    stack, and a bucket tripping mid-test would mask it. They must stay above zero, because that is
    what registers `CheckAuthenticatedRateLimitMiddleware` -- the `BaseHTTPMiddleware` at
    `BEFORE_VALIDATION` whose addition regressed the ceiling in the first place.
    """
    return {
        'max_upload_size': max_upload_size,
        'access': {'max_request_per_minute': 100000, 'max_unauthenticated_request_per_minute': 100000},
        'cors': {'enabled': cors, 'source_route': '*', 'expose_headers': '*', 'allow_headers': '*',
                 'allow_credentials': False},
    }


def build_app(api_conf: dict) -> AsyncApp:
    """Build a connexion application whose middleware stack is the API's own.

    The error handlers are registered exactly as `wazuh_manager_apid.start()` registers them.
    Without `problem_error_handler` the two refusal paths do not render the same way here as they do
    in production -- connexion's own rendering of a `ProblemException` reports `code`/`status` where
    the API reports `error` -- so the assertions below would be comparing against a body no caller
    ever receives.
    """
    app = AsyncApp(__name__)
    app.add_api(SPEC, resolver=Resolver(function_resolver=lambda name: HANDLERS[name]),
                strict_validation=True, validate_responses=False)
    with patch.object(middlewares.configuration, 'api_conf', new=api_conf):
        setup_middlewares(app)
    app.add_error_handler(ContentSizeExceeded, content_size_handler)
    app.add_error_handler(ExpectFailedException, expect_failed_error_handler)
    app.add_error_handler(ProblemException, problem_error_handler)
    return app


@pytest.fixture
def clean_rate_limit_state():
    """Keep the rate limiters' module level state from leaking between tests."""
    middlewares.ip_stats.clear()
    middlewares.ip_block.clear()
    yield
    middlewares.ip_stats.clear()
    middlewares.ip_block.clear()


def middleware_classes(app: AsyncApp) -> list:
    """List the stack's middleware classes, outermost first."""
    return [getattr(m, 'func', m) for m in app.middleware.middlewares]


def test_setup_middlewares_keeps_the_size_ceiling_below_every_basehttpmiddleware():
    """Check that no BaseHTTPMiddleware is registered below `ContentSizeLimitMiddleware`.

    This is the invariant that makes an oversized body a 413. It is asserted on the assembled stack
    rather than on the registration order so that moving a middleware to another position, not just
    adding one after the ceiling, is caught too.
    """
    classes = middleware_classes(build_app(build_api_conf()))

    assert ContentSizeLimitMiddleware in classes, "the size ceiling was not registered at all"
    below = classes[classes.index(ContentSizeLimitMiddleware) + 1:]
    offenders = [c.__name__ for c in below if isinstance(c, type) and issubclass(c, BaseHTTPMiddleware)]

    assert offenders == [], \
        f"{offenders} are registered below ContentSizeLimitMiddleware, which turns an oversized " \
        f"body into a 500 instead of a 413. Register them inside setup_middlewares(), above the ceiling."


def test_setup_middlewares_registers_no_ceiling_when_max_upload_size_is_zero():
    """Check that `max_upload_size: 0` means no limit, as the configuration documents."""
    classes = middleware_classes(build_app(build_api_conf(max_upload_size=0)))

    assert ContentSizeLimitMiddleware not in classes


@pytest.mark.parametrize('path, method, content_type, body, expected', [
    ('/groups', 'POST', 'application/json',
     b'{"group_id":"' + b'x' * (MAX_UPLOAD_SIZE + 500) + b'"}', {"message": "ok"}),
    ('/upload', 'PUT', 'application/octet-stream',
     b'x' * (MAX_UPLOAD_SIZE + 500), {"length": MAX_UPLOAD_SIZE + 500}),
], ids=['json', 'binary'])
@pytest.mark.parametrize('expect_header', [None, '100-continue'])
def test_zero_upload_limit_accepts_body(path, method, content_type, body, expected, expect_header,
                                       clean_rate_limit_state):
    """A disabled upload limit accepts bodies with or without an Expect header."""
    api_conf = build_api_conf(max_upload_size=0)
    headers = {'Content-Type': content_type}
    if expect_header:
        headers['Expect'] = expect_header

    with patch.object(middlewares.configuration, 'api_conf', new=api_conf), \
         patch('api.middlewares.access_log'):
        with TestClient(build_app(api_conf)) as client:
            response = client.request(method, path, content=body, headers=headers)

    assert response.status_code == 200
    assert response.json() == expected


def test_setup_middlewares_keeps_the_ceiling_innermost_with_cors_enabled():
    """Check that enabling CORS does not push a middleware below the ceiling."""
    classes = middleware_classes(build_app(build_api_conf(cors=True)))

    below = classes[classes.index(ContentSizeLimitMiddleware) + 1:]

    assert [c for c in below if isinstance(c, type) and issubclass(c, BaseHTTPMiddleware)] == []


@pytest.mark.parametrize('path, method, content_type, body_builder', [
    # Validation reads this body, so the ceiling is crossed above CheckExpectHeaderMiddleware.
    ('/groups', 'POST', 'application/json',
     lambda n: ('{"group_id":"' + 'x' * n + '"}').encode()),
    # Validation never reads this one: the ceiling is crossed at the endpoint, below every
    # middleware, which is what the original BEFORE_CONTEXT placement of the Expect middleware
    # swallowed.
    ('/upload', 'PUT', 'application/octet-stream', lambda n: b'x' * n),
])
@pytest.mark.parametrize('expect_header', [None, '100-continue'])
def test_oversized_body_is_refused_with_413(path, method, content_type, body_builder, expect_header,
                                            clean_rate_limit_state):
    """Check that a body above `max_upload_size` is refused with 413, whatever its shape.

    Asserts the whole response body, not just the status: the ceiling reached while reading and the
    one reached at the `Content-Length` header are two different middlewares raising two different
    exceptions through two different error handlers, and a caller must not be able to tell them
    apart. That is the body `RequestTooLargeResponse` publishes in spec.yaml.
    """
    api_conf = build_api_conf()
    body = body_builder(MAX_UPLOAD_SIZE + 500)
    client = TestClient(build_app(api_conf))
    headers = {'Content-Type': content_type}
    if expect_header:
        headers['Expect'] = expect_header

    with patch.object(middlewares.configuration, 'api_conf', new=api_conf), \
         patch('api.middlewares.access_log'):
        response = client.request(method, path, content=body, headers=headers)

    assert response.status_code == 413
    payload = response.json()
    assert set(payload) == {'title', 'detail', 'error'}
    assert payload['title'] == 'Request Entity Too Large'
    assert payload['error'] == 413
    if expect_header:
        # Refused at the header, so the reported size is exactly what the request declared.
        assert payload['detail'] == (f"Maximum content size limit ({MAX_UPLOAD_SIZE}) exceeded "
                                     f"({len(body)} bytes declared)")
    else:
        # Refused while reading, so the reported size is whatever had arrived when the limit was
        # crossed. That depends on how the server chunked the body, which is not our contract, so
        # only the shape of the message is pinned here.
        assert re.fullmatch(rf"Maximum content size limit \({MAX_UPLOAD_SIZE}\) exceeded "
                            rf"\(\d+ bytes read\)", payload['detail'])


@pytest.mark.parametrize('path, method, content_type, body, expected', [
    ('/groups', 'POST', 'application/json', b'{"group_id":"x"}', {"message": "ok"}),
    ('/upload', 'PUT', 'application/octet-stream', b'xxxx', {"length": 4}),
])
def test_body_below_the_ceiling_reaches_the_endpoint(path, method, content_type, body, expected,
                                                     clean_rate_limit_state):
    """Check that the ceiling does not disturb a request that fits under it."""
    api_conf = build_api_conf()
    client = TestClient(build_app(api_conf))

    with patch.object(middlewares.configuration, 'api_conf', new=api_conf), \
         patch('api.middlewares.access_log'):
        response = client.request(method, path, content=body, headers={'Content-Type': content_type})

    assert response.status_code == 200
    assert response.json() == expected
