# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

# --- Global patchers BEFORE importing modules under test ---
_uid_patcher = patch('wazuh.common.wazuh_uid')
_gid_patcher = patch('wazuh.common.wazuh_gid')
_uid_patcher.start()
_gid_patcher.start()

# Ensure RBAC ORM doesn't run real code at import-time
sys.modules.setdefault('wazuh.rbac.orm', MagicMock())

import wazuh.rbac.decorators
from wazuh.tests.util import RBAC_bypasser
from api.controllers.kvdb_controller import (
    get_kvdbs, post_kvdbs, put_kvdbs, delete_kvdbs
)
from wazuh import kvdb

# Bypass RBAC decorator
wazuh.rbac.decorators.expose_resources = RBAC_bypasser


def teardown_module():
    """Stop global patchers and cleanup after all tests in this module."""
    _uid_patcher.stop()
    _gid_patcher.stop()
    sys.modules.pop('wazuh.rbac.orm', None)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch('api.controllers.kvdb_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdb_controller.remove_nones_to_dict')
@patch('api.controllers.kvdb_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdb_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_kvdbs_defaults(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_kvdbs' endpoint wiring and default params."""
    result = await get_kvdbs()
    f_kwargs = {
        'policy_type': None,
        'ids': None,
        'offset': 0,
        'limit': None,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'search_in_fields': ['id', 'name', 'integration_id'],
        'q': None,
        'distinct': False
    }

    mock_dapi.assert_called_once_with(
        f=kvdb.list_kvdbs,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch('api.controllers.kvdb_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdb_controller.remove_nones_to_dict')
@patch('api.controllers.kvdb_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdb_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_kvdbs_with_ids(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_kvdbs' maps kvdb_id list to ids."""
    result = await get_kvdbs(kvdb_id=['a', 'b'], type_='production', offset=5, limit=10)

    f_kwargs = {
        'policy_type': 'production',
        'ids': ['a', 'b'],
        'offset': 5,
        'limit': 10,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'search_in_fields': ['id', 'name', 'integration_id'],
        'q': None,
        'distinct': False
    }

    mock_dapi.assert_called_once_with(
        f=kvdb.list_kvdbs,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch('api.controllers.kvdb_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdb_controller.remove_nones_to_dict')
@patch('api.controllers.kvdb_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdb_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_post_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'post_kvdbs' endpoint wiring."""
    body = {"id": "demo1", "name": "Demo", "content": {"k": "v"}}
    result = await post_kvdbs(body=body, type_="testing")

    f_kwargs = {'policy_type': 'testing', 'item': body}
    mock_dapi.assert_called_once_with(
        f=kvdb.create_kvdb,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch('api.controllers.kvdb_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdb_controller.remove_nones_to_dict')
@patch('api.controllers.kvdb_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdb_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_kvdbs' endpoint wiring."""
    body = {"id": "demo1", "name": "Demo (updated)", "content": {"k2": "v2"}}
    result = await put_kvdbs(body=body, type_="testing")

    f_kwargs = {'policy_type': 'testing', 'item': body}
    mock_dapi.assert_called_once_with(
        f=kvdb.update_kvdb,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdb_controller"], indirect=True)
@patch('api.controllers.kvdb_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdb_controller.remove_nones_to_dict')
@patch('api.controllers.kvdb_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdb_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_kvdbs' endpoint wiring."""
    result = await delete_kvdbs(type_="testing", kvdb_id=['a', 'b', 'c'])

    f_kwargs = {'policy_type': 'testing', 'ids': ['a', 'b', 'c']}
    mock_dapi.assert_called_once_with(
        f=kvdb.delete_kvdbs,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
