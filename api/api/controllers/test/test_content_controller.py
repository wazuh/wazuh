# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from wazuh.core.results import AffectedItemsWazuhResult


with patch("wazuh.common.wazuh_uid"):
    with patch("wazuh.common.wazuh_gid"):
        sys.modules["wazuh.rbac.orm"] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.content_controller import put_content_update
        from wazuh import content
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules["wazuh.rbac.orm"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["content_controller"], indirect=True)
@patch("api.controllers.content_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.content_controller.DistributedAPI.__init__", return_value=None)
async def test_put_content_update(mock_dapi, mock_dfunc, mock_request):
    """Verify 'put_content_update' endpoint is working as expected."""
    system_nodes_mock = AsyncMock()
    system_nodes_mock.return_value = ["master-node", "worker-node"]
    results = [
        ["master-node", "worker-node"],
        AffectedItemsWazuhResult(affected_items=["worker-node"], total_affected_items=1),
        AffectedItemsWazuhResult(affected_items=["master-node"], total_affected_items=1),
    ]
    with (
        patch("api.controllers.content_controller.get_system_nodes", return_value=system_nodes_mock),
        patch("api.controllers.content_controller.raise_if_exc", side_effect=results),
        patch("wazuh.content.update_content"),
    ):
        result = await put_content_update()
        mock_dapi.assert_any_call(
            f=content.update_content,
            request_type="distributed_master",
            is_async=False,
            wait_for_complete=True,
            logger=ANY,
            broadcasting=True,
            rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
            nodes=["worker-node"],
        )
        mock_dapi.assert_any_call(
            f=content.update_content,
            request_type="local_master",
            logger=ANY,
            rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
        )
        assert isinstance(result, ConnexionResponse)
