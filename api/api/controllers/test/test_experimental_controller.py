import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.experimental_controller import (clear_rootcheck_database,
                                                             clear_syscheck_database,
                                                             get_cis_cat_results,
                                                             get_hardware_info,
                                                             get_network_address_info,
                                                             get_network_interface_info,
                                                             get_network_protocol_info,
                                                             get_os_info,
                                                             get_packages_info,
                                                             get_ports_info,
                                                             get_processes_info,
                                                             get_hotfixes_info)
        from wazuh import ciscat
        from wazuh import rootcheck
        from wazuh import syscheck
        from wazuh import syscollector
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
async def test_experimental_controller(mock_request):
    async def test_clear_rootcheck_database():
        calls = [call(f=rootcheck.clear,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await clear_rootcheck_database(request=mock_request,
                                                agents_list='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_clear_syscheck_database():
        calls = [call(f=syscheck.clear,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await clear_syscheck_database(request=mock_request,
                                               agents_list='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_cis_cat_results():
        calls = [call(f=ciscat.get_ciscat_results,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_cis_cat_results(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_hardware_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_hardware_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_network_address_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_address_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_network_interface_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_interface_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_network_protocol_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_protocol_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_os_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_os_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_packages_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_packages_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_ports_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_ports_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_processes_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_processes_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_hotfixes_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_hotfixes_info(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    aux_d = {'token_info': {'rbac_policies': 'rbac_policies_value'}}
    mock_request.__getitem__.side_effect = aux_d.__getitem__
    functions = [test_clear_rootcheck_database(),
                 test_clear_syscheck_database(),
                 test_get_cis_cat_results(),
                 test_get_hardware_info(),
                 test_get_network_address_info(),
                 test_get_network_interface_info(),
                 test_get_network_protocol_info(),
                 test_get_os_info(),
                 test_get_packages_info(),
                 test_get_ports_info(),
                 test_get_processes_info(),
                 test_get_hotfixes_info()
                 ]
    for test_funct in functions:
        with patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.experimental_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.experimental_controller.raise_if_exc', return_value={}) as mock_exc:
                    with patch('api.configuration.api_conf', return_value={'experimental_features': True}):
                        await test_funct
