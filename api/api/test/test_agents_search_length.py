# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Verify the `agents_search` spec parameter rejects an oversized `search` value on GET /agents
before the request ever reaches wazuh-db, mirroring how `limit`'s `maximum` is enforced."""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

with patch('wazuh.common.wazuh_uid'), patch('wazuh.common.wazuh_gid'):
    sys.modules['wazuh.rbac.orm'] = MagicMock()

from connexion import AsyncApp  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from api.uri_parser import APIUriParser  # noqa: E402
import api.authentication as authentication  # noqa: E402

SPEC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'spec')
MAX_LENGTH = 1024


def _build_client():
    """Build a minimal connexion app serving the real spec.yaml, with authentication bypassed."""
    app = AsyncApp(__name__, specification_dir=SPEC_DIR, pythonic_params=True, uri_parser_class=APIUriParser)
    app.add_api('spec.yaml', strict_validation=True, validate_responses=False)
    return TestClient(app)


def test_agents_search_too_long_is_rejected_before_reaching_wdb():
    """GET /agents?search=<1025 chars> must be rejected with 400 by the spec validator, naming the
    maxLength limit, instead of reaching wazuh-db (which is what let it hit the socket's 65536-byte cap)."""
    with patch.object(authentication, 'decode_token', new=AsyncMock(return_value={'sub': 'wazuh', 'rbac_policies': {}})):
        client = _build_client()
        response = client.get('/agents', params={'search': 'a' * (MAX_LENGTH + 1)},
                               headers={'Authorization': 'Bearer test-token'})

    assert response.status_code == 400
    body = response.text
    assert 'maxLength' in body
    assert str(MAX_LENGTH) in body


def test_agents_search_at_max_length_is_not_rejected_by_the_validator():
    """A `search` value exactly at the 1024-char limit must not be rejected by the schema validator
    (any failure past that point belongs to a different layer, not the maxLength check)."""
    with patch.object(authentication, 'decode_token', new=AsyncMock(return_value={'sub': 'wazuh', 'rbac_policies': {}})):
        client = _build_client()
        response = client.get('/agents', params={'search': 'a' * MAX_LENGTH},
                               headers={'Authorization': 'Bearer test-token'})

    assert not (response.status_code == 400 and 'maxLength' in response.text)
