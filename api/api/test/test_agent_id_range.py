# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Verify the AgentID/AgentIDListAll schemas allow the full range the manager can store an id in --
up to INT32_MAX (2147483647), the boundary of the signed 32-bit int the manager keeps this value
in -- and reject anything past it or equal to 0, both when creating an agent (POST /agents/insert,
AgentID) and when referencing existing ones with the `all` keyword allowed (DELETE /agents,
AgentIDListAll) (#38626).
"""

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
INT32_MAX = 2147483647


def _build_client():
    """Build a minimal connexion app serving the real spec.yaml, with authentication bypassed."""
    app = AsyncApp(__name__, specification_dir=SPEC_DIR, pythonic_params=True, uri_parser_class=APIUriParser)
    app.add_api('spec.yaml', strict_validation=True, validate_responses=False)
    return TestClient(app)


def _post_insert(agent_id: str):
    with patch.object(authentication, 'decode_token', new=AsyncMock(return_value={'sub': 'wazuh', 'rbac_policies': {}})):
        client = _build_client()
        return client.post('/agents/insert', json={'name': 'qa-agent', 'id': agent_id},
                            headers={'Authorization': 'Bearer test-token'})


def test_id_at_int32_max_is_not_rejected_by_the_schema():
    """2147483647 is the highest id the manager can store without overflowing; the schema must not
    reject it on length or format grounds (any failure past that point belongs to a different layer)."""
    response = _post_insert(str(INT32_MAX))
    assert not (response.status_code == 400 and ('maxLength' in response.text or 'format' in response.text))


def test_id_past_int32_max_is_rejected_before_reaching_authd():
    """One past INT32_MAX must be rejected by the schema, not silently truncated further down the
    pipeline into a negative id (the original defect in #38626)."""
    response = _post_insert(str(INT32_MAX + 1))
    assert response.status_code == 400


def test_id_zero_is_rejected_as_reserved_for_the_manager():
    response = _post_insert('000')
    assert response.status_code == 400


def _delete_agents(agents_list: str):
    with patch.object(authentication, 'decode_token', new=AsyncMock(return_value={'sub': 'wazuh', 'rbac_policies': {}})):
        client = _build_client()
        return client.request('DELETE', '/agents', params={'agents_list': agents_list, 'status': 'all'},
                               headers={'Authorization': 'Bearer test-token'})


def test_delete_agents_accepts_the_all_keyword():
    """AgentIDListAll must keep accepting the `all` keyword the plain AgentID schema does not."""
    response = _delete_agents('all')
    assert not (response.status_code == 400 and 'format' in response.text)


def test_delete_agents_accepts_id_at_int32_max():
    response = _delete_agents(str(INT32_MAX))
    assert not (response.status_code == 400 and 'format' in response.text)


def test_delete_agents_rejects_id_past_int32_max():
    """Referencing an existing agent through DELETE /agents must reject the same out-of-range ids
    POST /agents/insert does -- AgentIDListAll used to fall back to the unrelated numbers_or_all
    format, which had no upper bound at all."""
    response = _delete_agents(str(INT32_MAX + 1))
    assert response.status_code == 400


def test_delete_agents_rejects_id_zero():
    response = _delete_agents('000')
    assert response.status_code == 400
