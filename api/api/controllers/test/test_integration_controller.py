# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

with patch("wazuh.common.wazuh_uid"):
    with patch("wazuh.common.wazuh_gid"):
        sys.modules["wazuh.rbac.orm"] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.integration_controller import upsert_integration, get_integration, delete_integration
        from wazuh import integration as integration_framework
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules["wazuh.rbac.orm"]

TEST_INTEGRATION_BODY = {
    "type": "integration",
    "id": "int1",
    "name": "Integration 1",
    "documentation": "doc",
    "description": "desc",
    "status": "enabled",
    "kvdbs": [],
    "decoders": [],
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch("api.controllers.integration_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integration_controller.remove_nones_to_dict")
@patch("api.controllers.integration_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integration_controller.raise_if_exc", return_value=CustomAffectedItems())
@patch("api.controllers.integration_controller.Body.validate_content_type")
@patch("api.controllers.integration_controller.IntegrationCreateModel.get_kwargs", new_callable=AsyncMock)
async def test_upsert_integration(
    mock_get_kwargs, mock_validate, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request
):
    """Verify 'create_integration' works as expected."""
    # Mock get_kwargs to return the body as kwargs
    mock_get_kwargs.return_value = TEST_INTEGRATION_BODY

    result = await upsert_integration(body=TEST_INTEGRATION_BODY, type_="policy")
    f_kwargs = {"integration_content": TEST_INTEGRATION_BODY, "policy_type": "policy"}
    mock_dapi.assert_called_once_with(
        f=integration_framework.upsert_integration,
        f_kwargs=mock_remove.return_value,
        request_type="local_master",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch("api.controllers.integration_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integration_controller.remove_nones_to_dict")
@patch("api.controllers.integration_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integration_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_get_integrations(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_integrations' works as expected."""
    result = await get_integration(type_="policy", integration_id=["a", "b"])
    f_kwargs = {
        "policy_type": "policy",
        "ids": ["a", "b"],
        "offset": 0,
        "limit": None,
        "select": None,
        "sort_by": ["id"],
        "sort_ascending": True,
        "search_text": None,
        "complementary_search": None,
        "q": None,
        "status": None,
        "distinct": False,
    }
    mock_dapi.assert_called_once_with(
        f=integration_framework.get_integration,
        f_kwargs=mock_remove.return_value,
        request_type="local_any",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch("api.controllers.integration_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integration_controller.remove_nones_to_dict")
@patch("api.controllers.integration_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integration_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_delete_integration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_integration' works as expected."""
    result = await delete_integration(type_="policy", integration_id=["x"])
    f_kwargs = {"policy_type": "policy", "ids": ["x"]}
    mock_dapi.assert_called_once_with(
        f=integration_framework.delete_integration,
        f_kwargs=mock_remove.return_value,
        request_type="local_master",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)
