# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from connexion.lifecycle import ConnexionResponse

from api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.agent_controller import (
            add_agent, delete_agents, delete_groups,
            delete_multiple_agent_single_group,
            delete_single_agent_multiple_groups,
            delete_single_agent_single_group, get_agent_config,
            get_agent_fields, get_agent_key, get_agent_no_group, get_agent_outdated,
            get_agents_summary, get_agent_summary_os, get_agent_summary_status,
            get_agent_uninstall_permission, get_agent_upgrade, get_agents, get_agents_in_group,
            get_daemon_stats, get_component_stats, get_group_config, get_group_file,
            get_group_files, get_list_group, get_sync_agent, insert_agent, post_group,
            post_new_agent, put_agent_single_group, put_group_config,
            put_multiple_agent_single_group, put_upgrade_agents,
            put_upgrade_custom_agents, reconnect_agents, restart_agent,
            restart_agents, restart_agents_by_group, restart_agents_by_node)
        from wazuh import agent, stats
        from wazuh.core.common import DATABASE_LIMIT
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_delete_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_alist,
                            mock_request):
    """Verify 'delete_agents' endpoint is working as expected."""
    result = await delete_agents(agents_list=mock_alist)
    if 'all' in mock_alist:
        mock_alist = None
    f_kwargs = {'agent_list': mock_alist,
                'purge': False,
                'filters': {
                    'status': None,
                    'older_than': None,
                    'manager': None,
                    'version': None,
                    'group': None,
                    'node_name': None,
                    'name': None,
                    'ip': None,
                    'registerIP': mock_request.query_params.get('registerIP', None)
                },
                'q': None
                }
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = mock_request.query_params.get(field, None)
    mock_dapi.awaited_once_with(f=agent.delete_agents,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agents' endpoint is working as expected."""
    result = await get_agents()
    f_kwargs = {'agent_list': None,
                'offset': 0,
                'limit': DATABASE_LIMIT,
                'sort': None,
                'search': None,
                'select': None,
                'filters': {
                    'status': None,
                    'older_than': None,
                    'manager': None,
                    'version': None,
                    'group': None,
                    'node_name': None,
                    'name': None,
                    'ip': None,
                    'registerIP': mock_request.query_params.get('registerIP', None),
                    'group_config_status': None
                },
                'q': None,
                'distinct': False
                }
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = mock_request.query_params.get(field, None)
    mock_dapi.assert_called_once_with(f=agent.get_agents,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'add_agent' endpoint is working as expected."""
    with patch('api.controllers.agent_controller.Body.validate_content_type'):
        with patch('api.controllers.agent_controller.AgentAddedModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await add_agent()
            mock_dapi.assert_called_once_with(f=agent.add_agent,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='local_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_reconnect_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'reconnect_agents' endpoint is working as expected."""
    result = await reconnect_agents()
    f_kwargs = {'agent_list': '*'
                }
    mock_dapi.assert_called_once_with(f=agent.reconnect_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      broadcasting=True,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_restart_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'restart_agents' endpoint is working as expected."""
    result = await restart_agents()
    f_kwargs = {'agent_list': '*'
                }
    mock_dapi.assert_called_once_with(f=agent.restart_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=True,
                                      wait_for_complete=False,
                                      broadcasting=True,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_restart_agents_by_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'restart_agents_by_node' endpoint is working as expected."""
    with patch('api.controllers.agent_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await restart_agents_by_node(
                                              node_id='001')
        f_kwargs = {'node_id': '001',
                    'agent_list': '*'
                    }
        mock_dapi.assert_called_once_with(f=agent.restart_agents_by_node,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=True,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('api.controllers.agent_controller.check_component_configuration_pair')
async def test_get_agent_config(mock_check_pair, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                               mock_request):
    """Verify 'get_agent_config' endpoint is working as expected."""
    kwargs_param = {'configuration': 'configuration_value'
                    }
    result = await get_agent_config(**kwargs_param)
    f_kwargs = {'agent_list': [None],
                'component': None,
                'config': kwargs_param.get('configuration', None)
                }
    mock_dapi.assert_called_once_with(f=agent.get_agent_config,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_single_agent_multiple_groups(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                                  mock_request):
    """Verify 'delete_single_agent_multiple_groups' endpoint is working as expected."""
    result = await delete_single_agent_multiple_groups(agent_id='001')
    f_kwargs = {'agent_list': ['001'],
                'group_list': None
                }
    mock_dapi.assert_called_once_with(f=agent.remove_agent_from_groups,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_sync_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_sync_agent' endpoint is working as expected."""
    result = await get_sync_agent(agent_id='001')
    f_kwargs = {'agent_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=agent.get_agents_sync_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_single_agent_single_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                               mock_request):
    """Verify 'delete_single_agent_single_group' endpoint is working as expected."""
    result = await delete_single_agent_single_group(agent_id='001', group_id='001')
    f_kwargs = {'agent_list': ['001'],
                'group_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=agent.remove_agent_from_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_agent_single_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'put_agent_single_group' endpoint is working as expected."""
    result = await put_agent_single_group(agent_id='001', group_id='001')
    f_kwargs = {'agent_list': ['001'],
                'group_list': ['001'],
                'replace': False
                }
    mock_dapi.assert_called_once_with(f=agent.assign_agents_to_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_key(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_key' endpoint is working as expected."""
    result = await get_agent_key(agent_id='001')
    f_kwargs = {'agent_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=agent.get_agents_keys,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_restart_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'restart_agent' endpoint is working as expected."""
    result = await restart_agent(
                                 agent_id='001')
    f_kwargs = {'agent_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=agent.restart_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=True,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@pytest.mark.parametrize('agents_list', [
    (['all']),
    (['001', '002']),
])
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_upgrade_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                  agents_list, mock_request):
    """Verify 'put_upgrade_agents' endpoint is working as expected."""
    result = await put_upgrade_agents(agents_list=agents_list)

    if 'all' in agents_list:
        agents_list = '*'
    f_kwargs = {'agent_list': agents_list,
                'wpk_repo': None,
                'version': None,
                'use_http': False,
                'force': False,
                'package_type': None,
                'filters': {
                    'manager': None,
                    'version': None,
                    'group': None,
                    'node_name': None,
                    'name': None,
                    'ip': None,
                    'registerIP': mock_request.query_params.get('registerIP', None)
                },
                'q': None
                }

    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = mock_request.query_params.get(field, None)

    mock_dapi.assert_called_once_with(f=agent.upgrade_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                      broadcasting=agents_list == '*'
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@pytest.mark.parametrize('agents_list, file_path',  [
    (['all'], '/var/ossec/valid_file.wpk'),
    (['001', '002'], '/var/ossec/var/upgrade/valid_file.wpk'),
    (['001'], '/var/ossec/wrong_file.txt')
])
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_upgrade_custom_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                         agents_list, file_path, mock_request):
    """Verify 'put_upgrade_custom_agents' endpoint is working as expected."""
    result = await put_upgrade_custom_agents(agents_list=agents_list, file_path=file_path)

    if 'all' in agents_list:
        agents_list = '*'
    f_kwargs = {'agent_list': agents_list,
                'file_path': file_path,
                'installer': None,
                'filters': {
                    'manager': None,
                    'version': None,
                    'group': None,
                    'node_name': None,
                    'name': None,
                    'ip': None,
                    'registerIP': mock_request.query_params.get('registerIP', None)
                },
                'q': None
                }

    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = mock_request.query_params.get(field, None)

    mock_dapi.assert_called_once_with(f=agent.upgrade_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                      broadcasting=agents_list == '*'
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_daemon_stats(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_daemon_stats' function is working as expected."""
    result = await get_daemon_stats(agent_id='001',
                                    daemons_list=['daemon_1', 'daemon_2'])

    f_kwargs = {'agent_list': ['001'],
                'daemons_list': ['daemon_1', 'daemon_2']}
    mock_dapi.assert_called_once_with(f=stats.get_daemons_stats_agents,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'])
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)

    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_component_stats(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_component_stats' endpoint is working as expected."""
    result = await get_component_stats()
    f_kwargs = {'agent_list': [None],
                'component': None
                }
    mock_dapi.assert_called_once_with(f=stats.get_agents_component_stats_json,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_upgrade(mock_exc, mock_dapi, mock_remove, mock_dfunc,
                                 mock_exp, mock_request):
    """Verify 'get_agent_upgrade' endpoint is working as expected."""
    result = await get_agent_upgrade()
    f_kwargs = {'agent_list': None,
                'filters': {
                    'manager': None,
                    'version': None,
                    'group': None,
                    'node_name': None,
                    'name': None,
                    'ip': None,
                    'registerIP': mock_request.query_params.get('registerIP', None)
                },
                'q': None
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = mock_request.query_params.get(field, None)

    mock_dapi.assert_called_once_with(f=agent.get_upgrade_result,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_post_new_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'post_new_agent' endpoint is working as expected."""
    result = await post_new_agent(
                                  agent_name='agent_name_value')
    # `ip` and `force` come from the API model
    f_kwargs = {
        'name': 'agent_name_value',
        'ip': None,
        'force': {
            'enabled': False,
            'disconnected_time': {
                'enabled': True,
                'value': '1h'
            },
            'after_registration_time': '1h'
        }
    }
    mock_dapi.assert_called_once_with(f=agent.add_agent,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_delete_multiple_agent_single_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_alist,
                                                 mock_request):
    """Verify 'delete_multiple_agent_single_group' endpoint is working as expected."""
    result = await delete_multiple_agent_single_group(
                                                      agents_list=mock_alist,
                                                      group_id='001')
    if 'all' in mock_alist:
        mock_alist = None
    f_kwargs = {'agent_list': mock_alist,
                'group_list': ['001']
                }
    mock_dapi.assert_called_once_with(f=agent.remove_agents_from_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_multiple_agent_single_group(mock_exc, mock_dapi, mock_remove, mock_dfunc,
                                               mock_exp, mock_request):
    """Verify 'put_multiple_agent_single_group' endpoint is working as expected."""
    result = await put_multiple_agent_single_group(
                                                   group_id='001',
                                                   agents_list='001')
    f_kwargs = {'agent_list': '001',
                'group_list': ['001'],
                'replace': False
                }
    mock_dapi.assert_called_once_with(f=agent.assign_agents_to_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_delete_groups(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_alist,
                            mock_request):
    """Verify 'delete_groups' endpoint is working as expected."""
    result = await delete_groups(
                                 groups_list=mock_alist)
    if 'all' in mock_alist:
        mock_alist = None
    f_kwargs = {'group_list': mock_alist
                }
    mock_dapi.assert_called_once_with(f=agent.delete_groups,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_list_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_list_group' endpoint is working as expected."""
    result = await get_list_group()
    hash_ = mock_request.query_params.get('hash', 'md5')
    f_kwargs = {'offset': 0,
                'limit': None,
                'group_list': None,
                'sort_by': ['name'],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'hash_algorithm': hash_,
                'q': None,
                'select': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=agent.get_agent_groups,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agents_in_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agents_in_group' endpoint is working as expected."""
    result = await get_agents_in_group(
                                       group_id='001')
    f_kwargs = {'group_list': ['001'],
                'offset': 0,
                'limit': DATABASE_LIMIT,
                'sort': None,
                'search': None,
                'select': None,
                'filters': {
                    'status': None,
                },
                'q': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=agent.get_agents_in_group,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_post_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'post_group' endpoint is working as expected."""
    with patch('api.controllers.agent_controller.Body.validate_content_type'):
        with patch('api.controllers.agent_controller.GroupAddedModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await post_group()
            mock_dapi.assert_called_once_with(f=agent.create_group,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='local_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_group_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_group_config' endpoint is working as expected."""
    result = await get_group_config(
                                    group_id='001')
    f_kwargs = {'group_list': ['001'],
                'offset': 0,
                'limit': DATABASE_LIMIT
                }
    mock_dapi.assert_called_once_with(f=agent.get_agent_conf,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_group_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'put_group_config' endpoint is working as expected."""
    with patch('api.controllers.agent_controller.Body.validate_content_type'):
        with patch('api.controllers.agent_controller.Body.decode_body') as mock_dbody:
            result = await put_group_config(
                                            group_id='001',
                                            body={})
            f_kwargs = {'group_list': ['001'],
                        'file_data': mock_dbody.return_value
                        }
            mock_dapi.assert_called_once_with(f=agent.upload_group_file,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_group_files(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_group_files' endpoint is working as expected."""
    result = await get_group_files(group_id='001')
    hash_ = mock_request.query_params.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'group_list': ['001'],
                'offset': 0,
                'limit': None,
                'sort_by': ["filename"],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'hash_algorithm': hash_,
                'q': None,
                'select': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=agent.get_group_files,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_group_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_group_file' endpoint is working as expected."""
    result = await get_group_file(group_id='001', file_name='filename_value')
    f_kwargs = {'group_list': ['001'],
                'filename': 'filename_value',
                'type_conf': mock_request.query_params.get('type', None),
                'raw': False
                }
    mock_dapi.assert_called_once_with(f=agent.get_file_conf,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@pytest.mark.parametrize('mock_alist', [CustomAffectedItems(empty=True), CustomAffectedItems()])
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.AffectedItemsWazuhResult', return_value={})
async def test_restart_agents_by_group(mock_aiwr, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_alist,
                                      mock_request):
    """Verify 'restart_agents_by_group' endpoint is working as expected."""
    with patch('api.controllers.agent_controller.raise_if_exc', return_value=mock_alist) as mock_exc:
        result = await restart_agents_by_group(group_id='001')
        f_kwargs = {'group_list': ['001'],
                    'select': ['id'],
                    'limit': None
                    }
        calls_get_agents = [call(f=agent.get_agents_in_group,
                                 f_kwargs=f_kwargs,
                                 request_type='local_master',
                                 is_async=False,
                                 wait_for_complete=False,
                                 logger=ANY,
                                 rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                 )
                            ]
        calls_restart_agents_by_group = [call(f=agent.restart_agents_by_group,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=True,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                              )
                                         ]
        if not mock_alist.affected_items:
            mock_dapi.assert_has_calls(calls_get_agents)
            assert mock_dapi.call_count == 1
            mock_aiwr.assert_called_once_with(none_msg='Restart command was not sent to any agent')
        else:
            f_kwargs = {'agent_list': [mock_exc.return_value.affected_items[0]['id']]
                        }
            mock_dapi.assert_has_calls(calls_get_agents,
                                       calls_restart_agents_by_group)
            assert mock_dapi.call_count == 2
            mock_exc.assert_has_calls([call(mock_dfunc.return_value),
                                       call(mock_dfunc.return_value)])
            assert mock_exc.call_count == 2
            mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.controllers.agent_controller.AgentInsertedModel.get_kwargs')
@patch('api.controllers.agent_controller.Body.validate_content_type')
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_insert_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                            mock_valid, mock_getkwargs, mock_request):
    """Verify 'insert_agent' endpoint is working as expected."""
    result = await insert_agent()
    mock_dapi.assert_called_once_with(f=agent.add_agent,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'])
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(mock_getkwargs.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_no_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_no_group' endpoint is working as expected."""
    result = await get_agent_no_group()
    f_kwargs = {'offset': 0,
                'limit': DATABASE_LIMIT,
                'select': None,
                'sort': None,
                'search': None,
                'q': 'id!=000;group=null'
                }
    mock_dapi.assert_called_once_with(f=agent.get_agents,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_outdated(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_outdated' endpoint is working as expected."""
    result = await get_agent_outdated()
    f_kwargs = {'offset': 0,
                'limit': DATABASE_LIMIT,
                'sort': None,
                'search': None,
                'select': None,
                'q': None
                }
    mock_dapi.assert_called_once_with(f=agent.get_outdated_agents,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_fields(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_fields' endpoint is working as expected."""
    result = await get_agent_fields()
    f_kwargs = {'offset': 0,
                'limit': DATABASE_LIMIT,
                'sort': None,
                'search': None,
                'fields': None,
                'q': None
                }
    mock_dapi.assert_called_once_with(f=agent.get_distinct_agents,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agents_summary(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_summary_status' endpoint is working as expected."""
    result = await get_agents_summary()
    f_kwargs = {'agent_list': None}
    mock_dapi.assert_called_once_with(f=agent.get_agents_summary,
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
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_summary_status(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                                       mock_request):
    """Verify 'get_agent_summary_status' endpoint is working as expected."""
    result = await get_agent_summary_status()
    mock_dapi.assert_called_once_with(f=agent.get_agents_summary_status,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_summary_os(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_summary_os' endpoint is working as expected."""
    result = await get_agent_summary_os()
    mock_dapi.assert_called_once_with(f=agent.get_agents_summary_os,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["agent_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.agent_controller.remove_nones_to_dict')
@patch('api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agent_uninstall_permission(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agent_uninstall_permission' endpoint is working as expected."""
    result = await get_agent_uninstall_permission()
    mock_dapi.assert_called_once_with(f=agent.check_uninstall_permission,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, ConnexionResponse)
