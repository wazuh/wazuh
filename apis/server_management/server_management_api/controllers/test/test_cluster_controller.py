# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from connexion.lifecycle import ConnexionResponse

from server_management_api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from server_management_api.controllers.cluster_controller import (
            get_cluster_nodes, get_conf_validation, get_configuration_node,
            get_healthcheck, get_info_node, get_log_node, get_log_summary_node,
            get_status, get_status_node, put_restart, update_configuration)
        from wazuh import cluster, manager
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_cluster_nodes(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_cluster_nodes' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_cluster_nodes()
        f_kwargs = {'filter_node': None,
                    'offset': 0,
                    'limit': None,
                    'sort': None,
                    'search': None,
                    'select': None,
                    'filter_type': mock_request.query_params.get('type', 'all'),
                    'q': None,
                    'distinct': False
                    }
        mock_dapi.assert_called_once_with(f=cluster.get_nodes_info,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_master',
                                          is_async=True,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          local_client_arg='lc',
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_healthcheck(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_healthcheck' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_healthcheck()
        f_kwargs = {'filter_node': None}
        mock_dapi.assert_called_once_with(f=cluster.get_health_nodes,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_master',
                                          is_async=True,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          local_client_arg='lc',
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_status(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_status' endpoint is working as expected."""
    result = await get_status()
    mock_dapi.assert_called_once_with(f=cluster.get_status_json,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=True,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_status_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_status_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_status_node(node_id='001')
        f_kwargs = {'node_id': '001'}
        mock_dapi.assert_called_once_with(f=manager.get_status,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
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
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_info_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_info_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_info_node(node_id='001')
        f_kwargs = {'node_id': '001'}
        mock_dapi.assert_called_once_with(f=manager.get_basic_info,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
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
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_get_configuration_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool,
                                      mock_request):
    """Verify 'get_configuration_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        with patch('api.controllers.cluster_controller.isinstance', return_value=mock_bool) as mock_isinstance:
            result = await get_configuration_node(node_id='001')
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
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                              nodes=mock_exc.return_value
                                              )
            mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                       call(mock_dfunc.return_value)])
            assert mock_exc.call_count == 2
            mock_remove.assert_called_once_with(f_kwargs)
            if mock_isinstance.return_value:
                assert isinstance(result, ConnexionResponse)
            else:
                assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_log_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_log_node(node_id='001')
        f_kwargs = {'node_id': '001',
                    'offset': 0,
                    'limit': None,
                    'sort_by': ['timestamp'],
                    'sort_ascending': False,
                    'search_text': None,
                    'complementary_search': None,
                    'tag': None,
                    'level': None,
                    'q': None,
                    'select': None,
                    'distinct': False
                    }
        mock_dapi.assert_called_once_with(f=manager.ossec_log,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
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
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_log_summary_node(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_log_summary_node' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_log_summary_node(node_id='001')
        f_kwargs = {'node_id': '001'}
        mock_dapi.assert_called_once_with(f=manager.ossec_log_summary,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
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
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_restart(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_restart' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await put_restart()
        f_kwargs = {'node_list': '*'}
        mock_dapi.assert_called_once_with(f=manager.restart,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          broadcasting=True,
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_conf_validation(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_conf_validation' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await get_conf_validation()
        f_kwargs = {'node_list': '*'}
        mock_dapi.assert_called_once_with(f=manager.validation,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          broadcasting=True,
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                          nodes=mock_exc.return_value
                                          )
        mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                   call(mock_dfunc.return_value)])
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with(f_kwargs)
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cluster_controller"], indirect=True)
@patch('api.controllers.cluster_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cluster_controller.remove_nones_to_dict')
@patch('api.controllers.cluster_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cluster_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_configuration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'update_configuration' endpoint is working as expected."""
    with patch('api.controllers.cluster_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        with patch('api.controllers.cluster_controller.Body.validate_content_type'):
            with patch('api.controllers.cluster_controller.Body.decode_body') as mock_dbody:
                result = await update_configuration(node_id='001',
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
                                                  rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                                  nodes=mock_exc.return_value
                                                  )
                mock_exc.assert_has_calls([call(mock_snodes.return_value),
                                           call(mock_dfunc.return_value)])
                assert mock_exc.call_count == 2
                mock_remove.assert_called_once_with(f_kwargs)
                assert isinstance(result, ConnexionResponse)
