# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

# --- Global patchers BEFORE importing modules under test ---
_uid_patcher = patch("wazuh.common.wazuh_uid")
_gid_patcher = patch("wazuh.common.wazuh_gid")
_uid_patcher.start()
_gid_patcher.start()

# Ensure RBAC ORM doesn't run real code at import-time
sys.modules.setdefault("wazuh.rbac.orm", MagicMock())

import wazuh.rbac.decorators
from wazuh.tests.util import RBAC_bypasser
from api.controllers.kvdb_controller import get_kvdb, upsert_kvdb, delete_kvdb
from wazuh import kvdb

# Bypass RBAC decorator
wazuh.rbac.decorators.expose_resources = RBAC_bypasser


def teardown_module():
    """Stop global patchers and cleanup after all tests in this module."""
    _uid_patcher.stop()
    _gid_patcher.stop()
    sys.modules.pop("wazuh.rbac.orm", None)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_get_kvdbs_defaults(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_kvdbs' endpoint wiring and default params."""
    result = await get_kvdb()
    f_kwargs = {
        "policy_type": None,
        "ids": [],
        "offset": 0,
        "limit": None,
        "select": None,
        "sort_by": ["id"],
        "sort_ascending": True,
        "search_text": None,
        "complementary_search": None,
        "search_in_fields": ["id", "name", "integration_id"],
        "q": None,
        "distinct": False,
    }

    mock_dapi.assert_called_once_with(
        f=kvdb.get_kvdb,
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
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_get_kvdbs_with_ids(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_kvdbs' maps kvdb_id list to ids."""
    result = await get_kvdb(kvdb_id=["a", "b"], type_="production", offset=5, limit=10)

    f_kwargs = {
        "policy_type": "production",
        "ids": ["a", "b"],
        "offset": 5,
        "limit": 10,
        "select": None,
        "sort_by": ["id"],
        "sort_ascending": True,
        "search_text": None,
        "complementary_search": None,
        "search_in_fields": ["id", "name", "integration_id"],
        "q": None,
        "distinct": False,
    }

    mock_dapi.assert_called_once_with(
        f=kvdb.get_kvdb,
        f_kwargs=mock_remove.return_value,
        request_type="local_any",
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context["token_info"]["rbac_policies"],
    )
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_upsert_kvdb(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'upsert_kvdb' endpoint wiring."""
    with patch("api.controllers.decoder_controller.Body.validate_content_type"):
        body = {"type": "testing", "id": "demo1", "name": "Demo", "content": {"k": "v"}}
        result = await upsert_kvdb(body=body, type_="testing")

        f_kwargs = {
            "policy_type": "testing",
            "kvdb_content": {"type": "testing", "id": "demo1", "name": "Demo", "content": {"k": "v"}, "integration_id": None},
        }
        mock_dapi.assert_called_once_with(
            f=kvdb.upsert_kvdb,
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
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_delete_kvdb(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_kvdbs' endpoint wiring."""
    result = await delete_kvdb(type_="testing", kvdb_id=["a", "b", "c"])

    f_kwargs = {"policy_type": "testing", "ids": ["a", "b", "c"]}
    mock_dapi.assert_called_once_with(
        f=kvdb.delete_kvdb,
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
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_delete_kvdbs_defaults(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_kvdbs' default wiring (no ids, no type)."""
    result = await delete_kvdb()

    f_kwargs = {"policy_type": None, "ids": []}
    mock_dapi.assert_called_once_with(
        f=kvdb.delete_kvdb,
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
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch("api.controllers.kvdb_controller.DistributedAPI.distribute_function", return_value=AsyncMock())
@patch("api.controllers.kvdb_controller.remove_nones_to_dict")
@patch("api.controllers.kvdb_controller.DistributedAPI.__init__", return_value=None)
@patch("api.controllers.kvdb_controller.raise_if_exc", return_value=CustomAffectedItems())
async def test_upsert_kvdb_with_integration_id(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Ensure integration_id is forwarded when provided."""
    with patch("api.controllers.decoder_controller.Body.validate_content_type"):
        body = {"type": "testing", "id": "demo1", "name": "Demo", "content": {"k": "v"}, "integration_id": "int-123"}
        result = await upsert_kvdb(body=body, type_="testing")

        f_kwargs = {"policy_type": "testing", "kvdb_content": body}
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)
