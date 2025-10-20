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
        from api.controllers.decoder_controller import (
            get_decoder,
            upsert_decoder,
            delete_decoder,
        )
        from wazuh import decoder as decoder_framework
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules["wazuh.rbac.orm"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["decoder_controller"], indirect=True)
@patch("api.controllers.decoder_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.decoder_controller.remove_nones_to_dict")
@patch("api.controllers.decoder_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.decoder_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_get_decoder(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_decoder' endpoint is working as expected."""
    result = await get_decoder()
    f_kwargs = {
        "ids": [],
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
        "policy_type": None,
    }
    mock_dapi.assert_called_once_with(
        f=decoder_framework.get_decoder,
        f_kwargs=mock_remove.return_value,
        request_type="local_any",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["decoder_controller"], indirect=True)
@patch("api.controllers.decoder_controller.DecodersModel.get_kwargs", new_callable=AsyncMock)
@patch("api.controllers.decoder_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.decoder_controller.remove_nones_to_dict")
@patch("api.controllers.decoder_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.decoder_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_upsert_decoder(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_get_kwargs, mock_request):
    """Verify 'create_decoder' endpoint is working as expected."""
    with patch("api.controllers.decoder_controller.Body.validate_content_type"):
        mock_get_kwargs.return_value = {"id": "test-decoder"}
        result = await upsert_decoder(body=b"dummy")
        f_kwargs = {
            "decoder_content": mock_get_kwargs.return_value,
            "policy_type": None,
        }
        mock_dapi.assert_called_once_with(
            f=decoder_framework.upsert_decoder,
            f_kwargs=mock_remove.return_value,
            request_type="local_master",
            is_async=True,
            wait_for_complete=False,
            logger=ANY,
            rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
        )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["decoder_controller"], indirect=True)
@patch("api.controllers.decoder_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.decoder_controller.remove_nones_to_dict")
@patch("api.controllers.decoder_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.decoder_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_delete_decoder(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_decoder' endpoint is working as expected."""
    result = await delete_decoder()
    f_kwargs = {
        "ids": [],
        "policy_type": None,
    }
    mock_dapi.assert_called_once_with(
        f=decoder_framework.delete_decoder,
        f_kwargs=mock_remove.return_value,
        request_type="local_master",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
