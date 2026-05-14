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
        from api.controllers.rootcheck_controller import (delete_rootcheck,
                                                          get_last_scan_agent,
                                                          get_rootcheck_agent,
                                                          put_rootcheck)
        from wazuh import rootcheck
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rootcheck_controller"], indirect=True)
@patch('api.controllers.rootcheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rootcheck_controller.remove_nones_to_dict')
@patch('api.controllers.rootcheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rootcheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_rootcheck(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_rootcheck' endpoint is working as expected."""
    result = await put_rootcheck()
    f_kwargs = {'agent_list': '*'
                }
    mock_dapi.assert_called_once_with(f=rootcheck.run,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=True,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rootcheck_controller"], indirect=True)
@patch('api.controllers.rootcheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rootcheck_controller.remove_nones_to_dict')
@patch('api.controllers.rootcheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rootcheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_rootcheck(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_rootcheck' endpoint is working as expected."""
    result = await delete_rootcheck()
    f_kwargs = {'agent_list': ['']
                }
    mock_dapi.assert_called_once_with(f=rootcheck.clear,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rootcheck_controller"], indirect=True)
@patch('api.controllers.rootcheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rootcheck_controller.remove_nones_to_dict')
@patch('api.controllers.rootcheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rootcheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rootcheck_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rootcheck_agent' endpoint is working as expected."""
    result = await get_rootcheck_agent()
    f_kwargs = {'agent_list': [None],
                'offset': 0,
                'limit': None,
                'sort': None,
                'search': None,
                'select': None,
                'q': '',
                'distinct': False,
                'filters': {
                    'status': 'all',
                    'pci_dss': None,
                    'cis': None
                    },
                }
    mock_dapi.assert_called_once_with(f=rootcheck.get_rootcheck_agent,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rootcheck_controller"], indirect=True)
@patch('api.controllers.rootcheck_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rootcheck_controller.remove_nones_to_dict')
@patch('api.controllers.rootcheck_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rootcheck_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_last_scan_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_last_scan_agent' endpoint is working as expected."""
    result = await get_last_scan_agent()
    f_kwargs = {'agent_list': [None]
                }
    mock_dapi.assert_called_once_with(f=rootcheck.get_last_scan,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
