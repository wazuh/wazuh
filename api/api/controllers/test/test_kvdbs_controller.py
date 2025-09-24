# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.kvdbs_controller import (
            get_kvdbs, post_kvdbs, put_kvdbs, delete_kvdbs
        )
        from wazuh import kvdbs
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdbs_controller"], indirect=True)
@patch('api.controllers.kvdbs_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdbs_controller.remove_nones_to_dict')
@patch('api.controllers.kvdbs_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdbs_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
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
        f=kvdbs.list_kvdbs,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdbs_controller"], indirect=True)
@patch('api.controllers.kvdbs_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdbs_controller.remove_nones_to_dict')
@patch('api.controllers.kvdbs_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdbs_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_post_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'post_kvdbs' endpoint wiring."""
    body = {"type": "kvdb", "id": "demo1", "name": "Demo", "content": {"k": "v"}}
    result = await post_kvdbs(body=body, type_="testing")

    f_kwargs = {'policy_type': 'testing', 'item': body}
    mock_dapi.assert_called_once_with(
        f=kvdbs.upsert_kvdb,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdbs_controller"], indirect=True)
@patch('api.controllers.kvdbs_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdbs_controller.remove_nones_to_dict')
@patch('api.controllers.kvdbs_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdbs_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_kvdbs' endpoint wiring."""
    body = {"type": "kvdb", "id": "demo1", "name": "Demo (updated)", "content": {"k2": "v2"}}
    result = await put_kvdbs(body=body, type_="testing")

    f_kwargs = {'policy_type': 'testing', 'item': body}
    mock_dapi.assert_called_once_with(
        f=kvdbs.upsert_kvdb,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["kvdbs_controller"], indirect=True)
@patch('api.controllers.kvdbs_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.kvdbs_controller.remove_nones_to_dict')
@patch('api.controllers.kvdbs_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.kvdbs_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_kvdbs(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_kvdbs' endpoint wiring."""
    result = await delete_kvdbs(type_="testing", kvdbs_list="a,b,c")

    f_kwargs = {'policy_type': 'testing', 'ids': ['a', 'b', 'c']}
    mock_dapi.assert_called_once_with(
        f=kvdbs.delete_kvdbs,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)