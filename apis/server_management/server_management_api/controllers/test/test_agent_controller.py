# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse

from server_management_api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh import agent
        from wazuh.core.common import DATABASE_LIMIT
        from wazuh.tests.util import RBAC_bypasser

        from server_management_api.controllers.agent_controller import (
            add_agent,
            delete_agents,
            delete_groups,
            delete_multiple_agent_single_group,
            get_agents,
            get_agents_in_group,
            get_group_config,
            get_list_group,
            post_group,
            put_group_config,
            put_multiple_agent_single_group,
            reconnect_agents,
            restart_agent,
            restart_agents,
        )

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', (['0191480e-7f67-7fd3-8c52-f49a3176360b'], ['all']))
async def test_delete_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_alist, mock_request):
    """Verify 'delete_agents' endpoint is working as expected."""
    filters = {
        'name': 'test',
        'group': 'test_group',
        'type': 'agent',
        'version': 'v5.0.0',
        'older_than': '1d',
        'is_connected': True,
    }
    result = await delete_agents(agents_list=mock_alist, **filters)
    if 'all' in mock_alist:
        mock_alist = []
    f_kwargs = {
        'agent_list': mock_alist,
        'filters': {
            'name': 'test',
            'groups': 'test_group',
            'type': 'agent',
            'version': 'v5.0.0',
            'last_login': '1d',
            'is_connected': True,
            'host.ip': mock_request.query_params.get('remote.ip', None),
            'host.os.full': mock_request.query_params.get('os.full', None),
        },
    }

    mock_dapi.awaited_once_with(
        f=agent.delete_agents,
        f_kwargs=mock_remove.return_value,
        request_type='local_any',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agents' endpoint is working as expected."""
    result = await get_agents()

    f_kwargs = {
        'agent_list': [],
        'filters': {
            'name': None,
            'groups': None,
            'type': None,
            'version': None,
            'last_login': None,
            'is_connected': None,
            'host.ip': None,
            'host.os.full': None,
        },
        'offset': 0,
        'limit': DATABASE_LIMIT,
        'select': None,
        'sort': None,
    }

    mock_dapi.assert_called_once_with(
        f=agent.get_agents,
        f_kwargs=mock_remove.return_value,
        request_type='local_any',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'add_agent' endpoint is working as expected."""
    with patch('server_management_api.controllers.agent_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.agent_controller.AgentRegistrationModel.get_kwargs',
            return_value=AsyncMock(),
        ) as mock_getkwargs:
            result = await add_agent()
            mock_dapi.assert_called_once_with(
                f=agent.add_agent,
                f_kwargs=mock_remove.return_value,
                request_type='local_any',
                is_async=True,
                wait_for_complete=False,
                logger=ANY,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)
            assert result.status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_reconnect_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'reconnect_agents' endpoint is working as expected."""
    result = await reconnect_agents()
    f_kwargs = {'agent_list': '*'}
    mock_dapi.assert_called_once_with(
        f=agent.reconnect_agents,
        f_kwargs=mock_remove.return_value,
        request_type='distributed_master',
        is_async=False,
        wait_for_complete=False,
        broadcasting=True,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_restart_agents(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'restart_agents' endpoint is working as expected."""
    result = await restart_agents()
    mock_dapi.assert_called_once_with(
        f=agent.restart_agents,
        f_kwargs=mock_remove.return_value,
        request_type='local_any',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({'agent_list': []})
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.skip('To be implemented')
async def test_restart_agent(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'restart_agent' endpoint is working as expected."""
    result = await restart_agent(agent_id='001')
    f_kwargs = {'agent_list': ['001']}
    mock_dapi.assert_called_once_with(
        f=agent.restart_agents,
        f_kwargs=mock_remove.return_value,
        request_type='distributed_master',
        is_async=False,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_delete_multiple_agent_single_group(
    mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_alist, mock_request
):
    """Verify 'delete_multiple_agent_single_group' endpoint is working as expected."""
    result = await delete_multiple_agent_single_group(agents_list=mock_alist, group_id='001')
    if 'all' in mock_alist:
        mock_alist = None
    f_kwargs = {'agent_list': mock_alist, 'group_list': ['001']}
    mock_dapi.assert_called_once_with(
        f=agent.remove_agents_from_group,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_multiple_agent_single_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'put_multiple_agent_single_group' endpoint is working as expected."""
    result = await put_multiple_agent_single_group(group_id='001', agents_list='001')
    f_kwargs = {'agent_list': '001', 'group_list': ['001'], 'replace': False}
    mock_dapi.assert_called_once_with(
        f=agent.assign_agents_to_group,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_alist', ['001', 'all'])
async def test_delete_groups(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_alist, mock_request):
    """Verify 'delete_groups' endpoint is working as expected."""
    result = await delete_groups(groups_list=mock_alist)
    if 'all' in mock_alist:
        mock_alist = None
    f_kwargs = {'group_list': mock_alist}
    mock_dapi.assert_called_once_with(
        f=agent.delete_groups,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_list_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_list_group' endpoint is working as expected."""
    result = await get_list_group()
    hash_ = mock_request.query_params.get('hash', 'md5')
    f_kwargs = {
        'offset': 0,
        'limit': None,
        'group_list': None,
        'sort_by': ['name'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'hash_algorithm': hash_,
        'q': None,
        'select': None,
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=agent.get_agent_groups,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_agents_in_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_agents_in_group' endpoint is working as expected."""
    result = await get_agents_in_group(group_id='001')
    f_kwargs = {
        'group_list': ['001'],
        'offset': 0,
        'limit': 500,
        'sort_by': ['name'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'q': None,
        'select': None,
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=agent.get_agents_in_group,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_post_group(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'post_group' endpoint is working as expected."""
    with patch('server_management_api.controllers.agent_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.agent_controller.GroupAddedModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await post_group()
            mock_dapi.assert_called_once_with(
                f=agent.create_group,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                wait_for_complete=False,
                logger=ANY,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_group_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_group_config' endpoint is working as expected."""
    result = await get_group_config(group_id='001')
    f_kwargs = {'group_list': ['001']}
    mock_dapi.assert_called_once_with(
        f=agent.get_group_conf,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', ['agent_controller'], indirect=True)
@patch('server_management_api.configuration.api_conf')
@patch(
    'server_management_api.controllers.agent_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.agent_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.agent_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.agent_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_group_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'put_group_config' endpoint is working as expected."""
    with patch('server_management_api.controllers.agent_controller.Body.validate_content_type'):
        with patch('server_management_api.controllers.agent_controller.Body.decode_body') as mock_dbody:
            result = await put_group_config(group_id='001', body={})
            f_kwargs = {'group_list': ['001'], 'file_data': mock_dbody.return_value}
            mock_dapi.assert_called_once_with(
                f=agent.update_group_file,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                wait_for_complete=False,
                logger=ANY,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, ConnexionResponse)
