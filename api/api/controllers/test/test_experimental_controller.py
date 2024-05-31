# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems
from wazuh.core.exception import WazuhResourceNotFound

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.experimental_controller import (
            check_experimental_feature_value, clear_rootcheck_database,
            clear_syscheck_database, get_cis_cat_results, get_hardware_info,
            get_hotfixes_info, get_network_address_info,
            get_network_interface_info, get_network_protocol_info, get_os_info,
            get_packages_info, get_ports_info, get_processes_info)
        from wazuh import ciscat, rootcheck, syscheck, syscollector
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_clear_rootcheck_database(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                        mock_alist, mock_request):
    """Verify 'clear_rootcheck_database' endpoint is working as expected."""
    result = await clear_rootcheck_database(
                                            agents_list=mock_alist)
    if 'all' in mock_alist:
        mock_alist = '*'
    f_kwargs = {'agent_list': mock_alist
                }
    mock_dapi.assert_called_once_with(f=rootcheck.clear,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=mock_alist == '*',
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_clear_syscheck_database(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                       mock_alist, mock_request):
    """Verify 'clear_syscheck_database' endpoint is working as expected."""
    result = await clear_syscheck_database(
                                           agents_list=mock_alist)
    if 'all' in mock_alist:
        mock_alist = '*'
    f_kwargs = {'agent_list': mock_alist
                }
    mock_dapi.assert_called_once_with(f=syscheck.clear,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=mock_alist == '*',
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_cis_cat_results(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_cis_cat_results' endpoint is working as expected."""
    result = await get_cis_cat_results()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'benchmark': None,
                    'profile': None,
                    'fail': None,
                    'error': None,
                    'notchecked': None,
                    'unknown': None,
                    'score': None,
                    'pass': mock_request.query_params.get('pass', None)
                    }
                }
    mock_dapi.assert_called_once_with(f=ciscat.get_ciscat_results,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_hardware_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_hardware_info' endpoint is working as expected."""
    result = await get_hardware_info()
    filters = {
        'board_serial': None
    }
    nested = ['ram.free', 'ram.total', 'cpu.cores', 'cpu.mhz', 'cpu.name']
    for field in nested:
        filters[field] = mock_request.query_params.get(field, None)
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': filters,
                'element_type': 'hardware'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_network_address_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                        mock_request):
    """Verify 'get_network_address_info' endpoint is working as expected."""
    result = await get_network_address_info()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'iface_name': None,
                    'proto': None,
                    'address': None,
                    'broadcast': None,
                    'netmask': None
                },
                'element_type': 'netaddr'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_network_interface_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                          mock_request):
    """Verify 'get_network_interface_info' endpoint is working as expected."""
    result = await get_network_interface_info()
    filters = {
        'adapter': None,
        'type': mock_request.query_params.get('type', None),
        'state': None,
        'mtu': None
    }
    nested = ['tx.packets', 'rx.packets', 'tx.bytes', 'rx.bytes', 'tx.errors', 'rx.errors', 'tx.dropped', 'rx.dropped']
    for field in nested:
        filters[field] = mock_request.query_params.get(field, None)
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': filters,
                'element_type': 'netiface'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_network_protocol_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                         mock_request):
    """Verify 'get_network_protocol_info' endpoint is working as expected."""
    result = await get_network_protocol_info()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'iface': None,
                    'type': mock_request.query_params.get('type', None),
                    'gateway': None,
                    'dhcp': None
                },
                'element_type': 'netproto'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_os_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_os_info' endpoint is working as expected."""
    result = await get_os_info()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'os_name': None,
                    'architecture': None,
                    'os_version': None,
                    'version': None,
                    'release': None
                },
                'element_type': 'os'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_packages_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_packages_info' endpoint is working as expected."""
    result = await get_packages_info()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'vendor': None,
                    'name': None,
                    'architecture': None,
                    'format': mock_request.query_params.get('format', None),
                    'version': None
                },
                'element_type': 'packages'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_ports_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_ports_info' endpoint is working as expected."""
    result = await get_ports_info()
    filters = {
        'pid': None,
        'protocol': None,
        'tx_queue': None,
        'state': None,
        'process': None
    }
    nested = ['local.ip', 'local.port', 'remote.ip']
    for field in nested:
        filters[field] = mock_request.query_params.get(field, None)
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': filters,
                'element_type': 'ports'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_processes_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_processes_info' endpoint is working as expected."""
    result = await get_processes_info()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'state': None,
                    'pid': None,
                    'ppid': None,
                    'egroup': None,
                    'euser': None,
                    'fgroup': None,
                    'name': None,
                    'nlwp': None,
                    'pgrp': None,
                    'priority': None,
                    'rgroup': None,
                    'ruser': None,
                    'sgroup': None,
                    'suser': None
                },
                'element_type': 'processes'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_hotfixes_info(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_hotfixes_info' endpoint is working as expected."""
    result = await get_hotfixes_info()
    filters = {'hotfix': None
               }
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': filters,
                'element_type': 'hotfixes'
                }
    mock_dapi.assert_called_once_with(f=syscollector.get_item_agent,
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
@patch('api.controllers.experimental_controller.raise_if_exc')
async def test_check_experimental_feature_value(mock_exc):
    @check_experimental_feature_value
    async def func_():
        pass
    with patch('api.configuration.api_conf', new={'experimental_features': False}):
        await func_()
        mock_exc.assert_called_once_with(WazuhResourceNotFound(1122))
    with patch('api.configuration.api_conf', new={'experimental_features': True}):
        await func_()
