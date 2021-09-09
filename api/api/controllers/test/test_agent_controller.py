import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.agent_controller import (delete_agents,
                                                      get_agents,
                                                      add_agent,
                                                      reconnect_agents,
                                                      restart_agents,
                                                      restart_agents_by_node,
                                                      get_agent_config,
                                                      delete_single_agent_multiple_groups,
                                                      get_sync_agent,
                                                      delete_single_agent_single_group,
                                                      put_agent_single_group,
                                                      get_agent_key,
                                                      restart_agent,
                                                      put_upgrade_agents,
                                                      put_upgrade_custom_agents,
                                                      get_component_stats,
                                                      get_agent_upgrade,
                                                      post_new_agent,
                                                      delete_multiple_agent_single_group,
                                                      put_multiple_agent_single_group,
                                                      delete_groups,
                                                      get_list_group,
                                                      get_agents_in_group,
                                                      post_group,
                                                      get_group_config,
                                                      put_group_config,
                                                      get_group_files,
                                                      get_group_file_json,
                                                      get_group_file_xml,
                                                      restart_agents_by_group,
                                                      insert_agent,
                                                      get_agent_no_group,
                                                      get_agent_outdated,
                                                      get_agent_fields,
                                                      get_agent_summary_status,
                                                      get_agent_summary_os)
        from wazuh import agent, stats
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


class CustomMagicMockReturn(dict):
    affected_items = [{'id': '001'}]

    def __init__(self):
        super().__init__(self)
        super().__setitem__('data', 'data_value')


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
async def test_agent_controller(mock_request):
    async def test_delete_agents():
        calls = [call(f=agent.delete_agents,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_agents(request=mock_request,
                                     agents_list='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agents():
        calls = [call(f=agent.get_agents,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agents(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_add_agent():
        with patch('api.controllers.agent_controller.Body.validate_content_type'):
            with patch('api.controllers.agent_controller.AgentAddedModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.agent_controller.remove_nones_to_dict'):
                    calls = [call(f=agent.add_agent,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await add_agent(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_reconnect_agents():
        calls = [call(f=agent.reconnect_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies'],
                      broadcasting=True
                      )
                 ]
        result = await reconnect_agents(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_restart_agents():
        calls = [call(f=agent.restart_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies'],
                      broadcasting=True
                      )
                 ]
        result = await restart_agents(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_restart_agents_by_node():
        with patch('api.controllers.agent_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
            calls = [call(f=agent.restart_agents_by_node,
                          f_kwargs=ANY,
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=False,
                          logger=ANY,
                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                          nodes=mock_exc.return_value
                          )
                     ]
            await restart_agents_by_node(request=mock_request,
                                         node_id='001')
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                       call(mock_dfunc.return_value)])

    async def test_get_agent_config():
        calls = [call(f=agent.get_agent_config,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_config(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_single_agent_multiple_groups():
        calls = [call(f=agent.remove_agent_from_groups,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_single_agent_multiple_groups(request=mock_request,
                                                           agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_sync_agent():
        calls = [call(f=agent.get_agents_sync_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_sync_agent(request=mock_request,
                                      agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_single_agent_single_group():
        calls = [call(f=agent.remove_agent_from_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_single_agent_single_group(request=mock_request,
                                                        agent_id='001',
                                                        group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_agent_single_group():
        calls = [call(f=agent.assign_agents_to_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_agent_single_group(request=mock_request,
                                              agent_id='001',
                                              group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_key():
        calls = [call(f=agent.get_agents_keys,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_key(request=mock_request,
                                     agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_restart_agent():
        calls = [call(f=agent.restart_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await restart_agent(request=mock_request,
                                     agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_upgrade_agents():
        calls = [call(f=agent.upgrade_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_upgrade_agents(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_upgrade_custom_agents():
        calls = [call(f=agent.upgrade_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_upgrade_custom_agents(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_component_stats():
        calls = [call(f=stats.get_agents_component_stats_json,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_component_stats(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_upgrade():
        calls = [call(f=agent.get_upgrade_result,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_upgrade(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_post_new_agent():
        calls = [call(f=agent.add_agent,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await post_new_agent(request=mock_request,
                                      agent_name='agent_name_value')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_multiple_agent_single_group():
        calls = [call(f=agent.remove_agents_from_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_multiple_agent_single_group(request=mock_request,
                                                          group_id='001',
                                                          agents_list='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_multiple_agent_single_group():
        calls = [call(f=agent.assign_agents_to_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_multiple_agent_single_group(request=mock_request,
                                                       group_id='001',
                                                       agents_list='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_groups():
        calls = [call(f=agent.delete_groups,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_groups(request=mock_request,
                                     groups_list='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_list_group():
        calls = [call(f=agent.get_agent_groups,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_list_group(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agents_in_group():
        calls = [call(f=agent.get_agents_in_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agents_in_group(request=mock_request,
                                           group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_post_group():
        with patch('api.controllers.agent_controller.Body.validate_content_type'):
            with patch('api.controllers.agent_controller.GroupAddedModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.agent_controller.remove_nones_to_dict'):
                    calls = [call(f=agent.create_group,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await post_group(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_get_group_config():
        calls = [call(f=agent.get_agent_conf,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_group_config(request=mock_request,
                                        group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_group_config():
        with patch('api.controllers.agent_controller.Body.validate_content_type'):
            with patch('api.controllers.agent_controller.Body.decode_body'):
                with patch('api.controllers.agent_controller.remove_nones_to_dict'):
                    calls = [call(f=agent.upload_group_file,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await put_group_config(request=mock_request,
                                                    group_id='001',
                                                    body={})
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_get_group_files():
        calls = [call(f=agent.get_group_files,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_group_files(request=mock_request,
                                       group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_group_file_json():
        calls = [call(f=agent.get_file_conf,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_group_file_json(request=mock_request,
                                           group_id='001',
                                           file_name='filename_value')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_group_file_xml():
        calls = [call(f=agent.get_file_conf,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_group_file_xml(request=mock_request,
                                          group_id='001',
                                          file_name='filename_value')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, ConnexionResponse)

    async def test_restart_agents_by_group():
        calls = [call(f=agent.get_agents_in_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      ),
                 call(f=agent.restart_agents,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await restart_agents_by_group(request=mock_request,
                                               group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_has_calls(mock_dfunc.return_value, mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_restart_agents_by_group_empty_agent_list():
        calls = [call(f=agent.get_agents_in_group,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        mock_exc.return_value.affected_items = []
        result = await restart_agents_by_group(request=mock_request,
                                               group_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_insert_agent():
        with patch('api.controllers.agent_controller.Body.validate_content_type'):
            with patch('api.controllers.agent_controller.AgentInsertedModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.agent_controller.remove_nones_to_dict'):
                    calls = [call(f=agent.add_agent,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await insert_agent(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_get_agent_no_group():
        calls = [call(f=agent.get_agents,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_no_group(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_outdated():
        calls = [call(f=agent.get_outdated_agents,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_outdated(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_fields():
        calls = [call(f=agent.get_distinct_agents,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_fields(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_summary_status():
        calls = [call(f=agent.get_agents_summary_status,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_summary_status(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_agent_summary_os():
        calls = [call(f=agent.get_agents_summary_os,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_agent_summary_os(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    functions = [test_delete_agents(),
                 test_get_agents(),
                 test_add_agent(),
                 test_reconnect_agents(),
                 test_restart_agents(),
                 test_restart_agents_by_node(),
                 test_get_agent_config(),
                 test_delete_single_agent_multiple_groups(),
                 test_get_sync_agent(),
                 test_delete_single_agent_single_group(),
                 test_put_agent_single_group(),
                 test_get_agent_key(),
                 test_restart_agent(),
                 test_put_upgrade_agents(),
                 test_put_upgrade_custom_agents(),
                 test_get_component_stats(),
                 test_get_agent_upgrade(),
                 test_post_new_agent(),
                 test_delete_multiple_agent_single_group(),
                 test_put_multiple_agent_single_group(),
                 test_delete_groups(),
                 test_get_list_group(),
                 test_get_agents_in_group(),
                 test_post_group(),
                 test_get_group_config(),
                 test_put_group_config(),
                 test_get_group_files(),
                 test_get_group_file_json(),
                 test_get_group_file_xml(),
                 test_restart_agents_by_group(),
                 test_restart_agents_by_group_empty_agent_list(),
                 test_insert_agent(),
                 test_get_agent_no_group(),
                 test_get_agent_outdated(),
                 test_get_agent_fields(),
                 test_get_agent_summary_status(),
                 test_get_agent_summary_os()
                 ]
    for test_funct in functions:
        with patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.agent_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.agent_controller.raise_if_exc',
                           return_value=CustomMagicMockReturn()) as mock_exc:
                    with patch('api.configuration.api_conf', return_value={'use_only_authd': False}):
                        await test_funct
