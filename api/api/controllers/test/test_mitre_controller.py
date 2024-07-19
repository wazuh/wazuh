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
        from api.controllers.mitre_controller import (get_groups, get_metadata,
                                                      get_mitigations,
                                                      get_references,
                                                      get_software,
                                                      get_tactics,
                                                      get_techniques)
        from wazuh import mitre
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_metadata(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_metadata' endpoint is working as expected."""
    result = await get_metadata()
    mock_dapi.assert_called_once_with(f=mitre.mitre_metadata,
                                      f_kwargs={},
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_groups(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_groups' endpoint is working as expected."""
    result = await get_groups()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None,
        'distinct': False
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_groups,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_mitigations(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_mitigations' endpoint is working as expected."""
    result = await get_mitigations()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None,
        'distinct': False
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_mitigations,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_references(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_references' endpoint is working as expected."""
    result = await get_references()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_references,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_software(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_software' endpoint is working as expected."""
    result = await get_software()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None,
        'distinct': False
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_software,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'])

    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_tactics(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_tactics' endpoint is working as expected."""
    result = await get_tactics()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None,
        'distinct': False
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_tactics,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["mitre_controller"], indirect=True)
@patch('api.controllers.mitre_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.mitre_controller.remove_nones_to_dict')
@patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.mitre_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_techniques(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_techniques' endpoint is working as expected."""
    result = await get_techniques()
    f_kwargs = {
        'filters': {
            'id': None,
        },
        'offset': None,
        'limit': None,
        'sort_by': None,
        'sort_ascending': False,
        'search_text': None,
        'complementary_search': None,
        'select': None,
        'q': None,
        'distinct': False
    }
    mock_dapi.assert_called_once_with(f=mitre.mitre_techniques,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'])

    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
