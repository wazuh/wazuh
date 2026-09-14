# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Verify `offset` is bounded by the spec and that rejecting a parameter discloses neither the
schema that rejected it nor the submitted value. Uses the production parameter validator and error
handler, so the body is what a client receives."""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

with patch('wazuh.common.wazuh_uid'), patch('wazuh.common.wazuh_gid'):
    sys.modules['wazuh.rbac.orm'] = MagicMock()

from connexion import AsyncApp  # noqa: E402
from connexion.exceptions import ProblemException  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from api import error_handler  # noqa: E402
from api.parameter_validator import WazuhParameterValidator  # noqa: E402
from api.uri_parser import APIUriParser  # noqa: E402
import api.authentication as authentication  # noqa: E402

SPEC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'spec')
INT32_MAX = 2147483647


def _get(params, path='/agents'):
    """Send an authenticated GET through a connexion app serving the real spec.yaml."""
    app = AsyncApp(__name__, specification_dir=SPEC_DIR, pythonic_params=True, uri_parser_class=APIUriParser)
    app.add_api('spec.yaml', strict_validation=True, validate_responses=False,
                validator_map={'parameter': WazuhParameterValidator})
    app.add_error_handler(ProblemException, error_handler.problem_error_handler)

    with patch.object(authentication, 'decode_token', new=AsyncMock(return_value={'sub': 'wazuh', 'rbac_policies': {}})):
        return TestClient(app).get(path, params=params, headers={'Authorization': 'Bearer test-token'})


def test_offset_above_int32_is_rejected_before_reaching_wdb():
    """An `offset` past its int32 format must be rejected by the spec validator, the way `limit` is,
    instead of passing validation and being refused down in wazuh-db."""
    response = _get({'offset': INT32_MAX + 1})

    assert response.status_code == 400
    assert response.json()['detail'] == (f"Invalid value for query parameter 'offset': must be less than or "
                                         f"equal to {INT32_MAX}")


def test_offset_at_int32_max_is_not_rejected_by_the_validator():
    """An `offset` exactly at the limit must not be rejected by the schema validator (any failure
    past that point belongs to a different layer, not the maximum check)."""
    response = _get({'offset': INT32_MAX})

    assert not (response.status_code == 400 and 'offset' in response.text)


def test_rejected_parameter_does_not_disclose_the_schema():
    """A rejected parameter must report the violated constraint, not jsonschema's diagnostics: the
    subschema as a Python dict literal and its undocumented fields."""
    response = _get({'limit': -1})

    assert response.status_code == 400
    for leaked in ('Failed validating', 'On instance', "'default': 500", "'type': 'integer'"):
        assert leaked not in response.text
    assert response.json()['detail'] == "Invalid value for query parameter 'limit': must be greater than or equal to 1"


def test_rejected_parameter_does_not_echo_the_submitted_value():
    """A rejected parameter must not quote the submitted bytes back: the detail is what the caller
    receives."""
    response = _get({'groups_list': '\x00'}, path='/groups')

    assert response.status_code == 400
    assert '\\x00' not in response.text
    assert response.json()['detail'] == ("Invalid value for query parameter 'groups_list': must match the "
                                         "'group_names' format")
