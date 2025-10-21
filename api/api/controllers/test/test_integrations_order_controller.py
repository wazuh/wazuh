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
        from api.controllers.integrations_order_controller import (
            upsert_integrations_order,
            get_integrations_order,
            delete_integrations_order,
        )
        from wazuh import integrations_order as integrations_order_framework
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules["wazuh.rbac.orm"]

TEST_ORDER_BODY = [{"id": 1, "name": "apache"}, {"id": 2, "name": "cisco"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integrations_order_controller"], indirect=True)
@patch("api.controllers.integrations_order_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integrations_order_controller.remove_nones_to_dict")
@patch("api.controllers.integrations_order_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integrations_order_controller.raise_if_exc", return_value=CustomAffectedItems())
@patch("api.controllers.integrations_order_controller.Body.validate_content_type")
@patch("api.controllers.integrations_order_controller.IntegrationsOrderModel")
@patch("api.controllers.integrations_order_controller.IntegrationsOrder", return_value=MagicMock())
async def test_upsert_integrations_order(
    mock_order_model, mock_model_cls, mock_validate, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request
):
    """Verify 'upsert_integrations_order' works as expected."""
    mock_instance = MagicMock()
    mock_instance.order = [MagicMock(id=o["id"], name=o["name"]) for o in TEST_ORDER_BODY]
    mock_model_cls.return_value = mock_instance

    result = await upsert_integrations_order(body=TEST_ORDER_BODY, type_="policy")
    f_kwargs = {"order": mock_order_model.return_value, "policy_type": "policy"}
    mock_dapi.assert_called_once_with(
        f=integrations_order_framework.upsert_integrations_order,
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
@pytest.mark.parametrize("mock_request", ["integrations_order_controller"], indirect=True)
@patch("api.controllers.integrations_order_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integrations_order_controller.remove_nones_to_dict")
@patch("api.controllers.integrations_order_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integrations_order_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_get_integrations_order(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_integrations_order' works as expected."""
    result = await get_integrations_order(type_="policy")
    f_kwargs = {"policy_type": "policy"}
    mock_dapi.assert_called_once_with(
        f=integrations_order_framework.get_integrations_order,
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
@pytest.mark.parametrize("mock_request", ["integrations_order_controller"], indirect=True)
@patch("api.controllers.integrations_order_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.integrations_order_controller.remove_nones_to_dict")
@patch("api.controllers.integrations_order_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.integrations_order_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_delete_integrations_order(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_integrations_order' works as expected."""
    result = await delete_integrations_order(type_="policy")
    f_kwargs = {"policy_type": "policy"}
    mock_dapi.assert_called_once_with(
        f=integrations_order_framework.delete_integrations_order,
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
