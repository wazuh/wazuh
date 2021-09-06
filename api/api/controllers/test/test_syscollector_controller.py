import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.syscollector_controller import (get_hardware_info,
                                                             get_hotfix_info,
                                                             get_network_address_info,
                                                             get_network_interface_info,
                                                             get_network_protocol_info,
                                                             get_os_info,
                                                             get_packages_info,
                                                             get_ports_info,
                                                             get_processes_info)
        from wazuh import syscollector
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
async def test_syscollector_controller(mock_request):
    async def test_get_hardware_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_hardware_info(mock_request,
                                         agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_hotfix_info():
        calls = [call(f=syscollector.get_item_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_hotfix_info(mock_request,
                                       agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_address_info(mock_request,
                                                agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_interface_info(mock_request,
                                                  agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_network_protocol_info(mock_request,
                                                 agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_os_info(mock_request,
                                   agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_packages_info(mock_request,
                                         agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_ports_info(mock_request,
                                      agent_id='001')
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
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_processes_info(mock_request,
                                          agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    functions = [test_get_hardware_info(),
                 test_get_hotfix_info(),
                 test_get_network_address_info(),
                 test_get_network_interface_info(),
                 test_get_network_protocol_info(),
                 test_get_os_info(),
                 test_get_packages_info(),
                 test_get_ports_info(),
                 test_get_processes_info()
                 ]
    mock_request.request = {'aux', 'value2'}
    aux_d = {'token_info': {'rbac_policies': 'value1'}}
    mock_request.__getitem__.side_effect = aux_d.__getitem__
    for test_funct in functions:
        with patch('api.controllers.syscollector_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.syscollector_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.syscollector_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
