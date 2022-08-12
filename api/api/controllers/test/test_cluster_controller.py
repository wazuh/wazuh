import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response
from api.controllers.test.utils import CustomAffectedItems
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.cluster_controller import (
            get_api_config, get_cluster_node, get_cluster_nodes,
            get_conf_validation, get_config, get_configuration_node,
            get_healthcheck, get_info_node, get_log_node, get_log_summary_node,
            get_node_config, get_stats_analysisd_node, get_stats_hourly_node,
            get_stats_node, get_stats_remoted_node, get_stats_weekly_node,
            get_status, get_status_node, put_restart, update_configuration, get_nodes_ruleset_sync_status)
        from wazuh import cluster, common, manager, stats
        from wazuh.core.cluster import cluster as core_cluster
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_cluster_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_cluster_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_cluster_node(request=mock_request)
        mock_dapi.assert_called_once_with(f=cluster.get_node_wrapper,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_any',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with({})
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_cluster_nodes(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_cluster_nodes' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_cluster_nodes(request=mock_request)
        f_kwargs = {'filter_node': None,
                    'offset': 0,
                    'limit': None,
                    'sort': None,
                    'search': None,
                    'select': None,
                    'filter_type': mock_request.query.get('type', 'all'),
                    'q': None
                    }
        mock_dapi.assert_called_once_with(f=cluster.get_nodes_info,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_master',
                                          is_async=True,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          local_client_arg='lc',
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_healthcheck(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_healthcheck' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_healthcheck(request=mock_request)
        f_kwargs = {'filter_node': None
                    }
        mock_dapi.assert_called_once_with(f=cluster.get_health_nodes,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_master',
                                          is_async=True,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          local_client_arg='lc',
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_nodes_ruleset_sync_status(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_nodes_ruleset_sync_status' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_nodes_ruleset_sync_status(request=mock_request)
        f_kwargs = {'node_list': '*',
                    'master_md5': {'dikt_key': 'dikt_value'}
                    }
        mock_dapi.assert_has_calls([call(f=core_cluster.get_node_ruleset_integrity,
                                         request_type="local_master",
                                         is_async=True,
                                         wait_for_complete=False,
                                         logger=ANY,
                                         local_client_arg="lc"),
                                    call(f=cluster.get_ruleset_sync_status,
                                         f_kwargs=mock_remove.return_value,
                                         request_type="distributed_master",
                                         is_async=True,
                                         wait_for_complete=False,
                                         logger=ANY,
                                         rbac_permissions=mock_request['token_info']['rbac_policies'],
                                         nodes=mock_exc.return_value,
                                         broadcasting=True)])
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 3
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_status(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_status' endpoint is working as expected."""
    result = await get_status(request=mock_request)
    mock_dapi.assert_called_once_with(f=cluster.get_status_json,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_config' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_config(request=mock_request)
        mock_dapi.assert_called_once_with(f=cluster.read_config_wrapper,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_any',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with({})
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_status_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_status_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_status_node(request=mock_request,
                                       node_id='001')
        f_kwargs = {'node_id': '001'
                    }
        mock_dapi.assert_called_once_with(f=manager.get_status,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_info_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_info_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_info_node(request=mock_request,
                                     node_id='001')
        f_kwargs = {'node_id': '001'
                    }
        mock_dapi.assert_called_once_with(f=manager.get_basic_info,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_get_configuration_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool,
                                      mock_request=MagicMock()):
    """Verify 'get_configuration_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        with patch('api.controllers.cluster_controller.isinstance', return_value=mock_bool) as mock_isinstance:
            result = await get_configuration_node(request=mock_request,
                                                  node_id='001')
            f_kwargs = {'node_id': '001',
                        'section': None,
                        'field': None,
                        'raw': False
                        }
            mock_dapi.assert_called_once_with(f=manager.read_ossec_conf,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request['token_info']['rbac_policies'],
                                              nodes=mock_exc.return_value
                                              )
            mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                       call(mock_dfunc.return_value)])
            assert mock_exc.call_count == 2
            mock_remove.assert_called_once_with(f_kwargs)
            if mock_isinstance.return_value:
                assert isinstance(result, web_response.Response)
            else:
                assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_date', [None, 'date_value'])
async def test_get_stats_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_date, mock_request=MagicMock()):
    """Verify 'get_stats_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        with patch('api.controllers.cluster_controller.deserialize_date', return_value='desdate_value') as mock_desdate:
            result = await get_stats_node(request=mock_request,
                                          node_id='001',
                                          date=mock_date)
            if not mock_date:
                date = ANY
            else:
                mock_desdate.assert_called_once_with(mock_date)
                date = mock_desdate.return_value
            f_kwargs = {'node_id': '001',
                        'date': date
                        }
            mock_dapi.assert_called_once_with(f=stats.totals,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request['token_info']['rbac_policies'],
                                              nodes=mock_exc.return_value
                                              )
            mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                       call(mock_dfunc.return_value)])
            assert mock_exc.call_count == 2
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_hourly_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_hourly_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_stats_hourly_node(request=mock_request,
                                             node_id='001')
        f_kwargs = {'node_id': '001'
                    }
        mock_dapi.assert_called_once_with(f=stats.hourly,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_weekly_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_weekly_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_stats_weekly_node(request=mock_request,
                                             node_id='001')
        f_kwargs = {'node_id': '001'
                    }
        mock_dapi.assert_called_once_with(f=stats.weekly,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_analysisd_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_analysisd_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_stats_analysisd_node(request=mock_request,
                                                node_id='001')
        f_kwargs = {'node_id': '001',
                    'filename': common.analysisd_stats
                    }
        mock_dapi.assert_called_once_with(f=stats.get_daemons_stats,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_stats_remoted_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_stats_remoted_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_stats_remoted_node(request=mock_request,
                                              node_id='001')
        f_kwargs = {'node_id': '001',
                    'filename': common.remoted_stats
                    }
        mock_dapi.assert_called_once_with(f=stats.get_daemons_stats,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_log_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_log_node(request=mock_request,
                                    node_id='001')
        f_kwargs = {'node_id': '001',
                    'offset': 0,
                    'limit': None,
                    'sort_by': ['timestamp'],
                    'sort_ascending': False,
                    'search_text': None,
                    'complementary_search': None,
                    'tag': None,
                    'level': None,
                    'q': None
                    }
        mock_dapi.assert_called_once_with(f=manager.ossec_log,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log_summary_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_log_summary_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_log_summary_node(request=mock_request,
                                            node_id='001')
        f_kwargs = {'node_id': '001'
                    }
        mock_dapi.assert_called_once_with(f=manager.ossec_log_summary,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_api_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_api_config' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_api_config(request=mock_request)
        f_kwargs = {'node_list': '*'
                    }
        mock_dapi.assert_called_once_with(f=manager.get_api_config,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          broadcasting=True,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_restart(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'put_restart' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await put_restart(request=mock_request)
        f_kwargs = {'node_list': '*'
                    }
        mock_dapi.assert_called_once_with(f=manager.restart,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          broadcasting=True,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_conf_validation(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_conf_validation' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_conf_validation(request=mock_request)
        f_kwargs = {'node_list': '*'
                    }
        mock_dapi.assert_called_once_with(f=manager.validation,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          broadcasting=True,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_node_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'get_node_config' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        kwargs_param = {'configuration': 'configuration_value'
                        }
        result = await get_node_config(request=mock_request,
                                       node_id='001',
                                       component='component_value',
                                       **kwargs_param)
        f_kwargs = {'node_id': '001',
                    'component': 'component_value',
                    'config': kwargs_param.get('configuration', None)
                    }

        mock_dapi.assert_called_once_with(f=manager.get_config,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, web_response.Response)


@pytest.mark.asyncio
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_configuration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify 'update_configuration' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        with patch('api.controllers.cluster_controller.Body.validate_content_type'):
            with patch('api.controllers.cluster_controller.Body.decode_body') as mock_dbody:
                result = await update_configuration(request=mock_request,
                                                    node_id='001',
                                                    body={})
                f_kwargs = {'node_id': '001',
                            'new_conf': mock_dbody.return_value
                            }
                mock_dapi.assert_called_once_with(f=manager.update_ossec_conf,
                                                  f_kwargs=mock_remove.return_value,
                                                  request_type='distributed_master',
                                                  is_async=False,
                                                  wait_for_complete=False,
                                                  logger=ANY,
                                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                                  nodes=mock_exc.return_value
                                                  )
                mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                           call(mock_dfunc.return_value)])
                assert mock_exc.call_count == 2
                mock_remove.assert_called_once_with(f_kwargs)
                assert isinstance(result, web_response.Response)
