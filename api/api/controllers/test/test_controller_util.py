# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""api.controllers.util module unit tests."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.util import fill_master_uuid, json_response, build_recursion_error_response, ERROR_CONTENT_TYPE
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult

@pytest.mark.parametrize('pretty, body, status_code, content_type', 
                            [(False, '{"a": "1", "b": "2"}', 200, 'application/json'), 
                            (True, '{\n   "a": "1",\n   "b": "2"\n}', 401, 'application/json')
                         ])
def test_json_response(pretty, body, status_code, content_type):
    """Veryfy if the response body is converted to json and prettyfied."""
    data = {"a": "1", "b": "2"}
    response = json_response(data=data, pretty=pretty, content_type=content_type, status_code=status_code)
    assert isinstance(response, ConnexionResponse)
    assert response.body == body
    assert response.status_code == status_code
    assert response.content_type == content_type


def test_build_recursion_error_response():
    expected_problem = {
        "title": "Maximum recursion depth exceeded.",
        "detail": "The JSON structure of the request exceeds the maximum nesting depth allowed by the API."
    }

    mock_response = MagicMock()

    with patch('api.controllers.util.json_response', return_value=mock_response) as mock_json_response:
        resp = build_recursion_error_response(pretty=True)

        mock_json_response.assert_called_once_with(
            data=expected_problem,
            pretty=True,
            status_code=400,
            content_type=ERROR_CONTENT_TYPE
        )

        assert resp == mock_response


@pytest.mark.asyncio
@patch('api.controllers.util.DistributedAPI')
async def test_fill_master_uuid_worker(mock_dapi):
    """Verify a null uuid is replaced by the one the master returns."""
    mock_dapi.return_value.distribute_function = AsyncMock(return_value=WazuhResult({'uuid': 'master-uuid'}))
    data = AffectedItemsWazuhResult(affected_items=[{'uuid': None}])

    await fill_master_uuid(data)

    assert data.affected_items[0]['uuid'] == 'master-uuid'
    assert mock_dapi.call_args.kwargs['request_type'] == 'local_master'


@pytest.mark.asyncio
@patch('api.controllers.util.DistributedAPI')
async def test_fill_master_uuid_keeps_existing(mock_dapi):
    """Verify the master is not queried when the node already provides a uuid."""
    data = AffectedItemsWazuhResult(affected_items=[{'uuid': 'node-uuid'}])

    await fill_master_uuid(data)

    assert data.affected_items[0]['uuid'] == 'node-uuid'
    mock_dapi.assert_not_called()


@pytest.mark.asyncio
@patch('api.controllers.util.DistributedAPI')
async def test_fill_master_uuid_no_items(mock_dapi):
    """Verify the master is not queried when the node returned no info."""
    await fill_master_uuid(AffectedItemsWazuhResult())

    mock_dapi.assert_not_called()


@pytest.mark.asyncio
@patch('api.controllers.util.DistributedAPI')
async def test_fill_master_uuid_master_error(mock_dapi):
    """Verify the uuid stays null when the master cannot be reached."""
    mock_dapi.return_value.distribute_function = AsyncMock(return_value=WazuhError(3000))
    data = AffectedItemsWazuhResult(affected_items=[{'uuid': None}])

    await fill_master_uuid(data)

    assert data.affected_items[0]['uuid'] is None
