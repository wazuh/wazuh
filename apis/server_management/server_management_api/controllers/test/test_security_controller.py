# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from connexion.testing import TestContext
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.server import ValidateFilePathMixin

from server_management_api.controllers.test.utils import CustomAffectedItems, get_default_configuration
from server_management_api.controllers.util import JSON_CONTENT_TYPE

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            import wazuh.rbac.decorators
            from wazuh import security
            from wazuh.core.exception import WazuhException, WazuhPermissionError
            from wazuh.core.results import AffectedItemsWazuhResult
            from wazuh.rbac import preprocessor
            from wazuh.tests.util import RBAC_bypasser

            from server_management_api.controllers.security_controller import (
                add_policy,
                add_role,
                add_rule,
                create_user,
                delete_security_config,
                delete_users,
                edit_run_as,
                get_policies,
                get_rbac_actions,
                get_rbac_resources,
                get_roles,
                get_rules,
                get_security_config,
                get_user_me,
                get_user_me_policies,
                get_users,
                login_user,
                logout_user,
                put_security_config,
                remove_policies,
                remove_role_policy,
                remove_role_rule,
                remove_roles,
                remove_rules,
                remove_user_role,
                revoke_all_tokens,
                run_as_login,
                security_revoke_tokens,
                set_role_policy,
                set_role_rule,
                set_user_role,
                update_policy,
                update_role,
                update_rule,
                update_user,
            )

            wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.fixture
def mock_request():
    """Fixture to wrap functions with request."""
    operation = MagicMock(name='operation')
    operation.method = 'post'
    with TestContext(operation=operation):
        with patch('server_management_api.controllers.security_controller.request', MagicMock) as m_req:
            m_req.json = AsyncMock(side_effect=lambda: {'ctx': ''})
            m_req.get = MagicMock(return_value=None)
            m_req.query_params = MagicMock()
            m_req.query_params.get = MagicMock(return_value=None)
            m_req.context = {'token_info': {'sub': 'wazuh', 'run_as': 'manager', 'rbac_policies': {}}}
            m_req.state = MagicMock()
            yield m_req


@pytest.mark.asyncio
@pytest.mark.parametrize('raw', [True, False])
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.generate_token', return_value='token')
async def test_login_user(mock_token, mock_exc, mock_dapi, mock_remove, mock_dfunc, raw, mock_request):
    """Verify 'login_user' endpoint is working as expected."""
    result = await login_user(user='001', raw=raw)
    f_kwargs = {'user_id': '001'}
    mock_dapi.assert_called_once_with(
        f=preprocessor.get_permissions,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        rbac_manager=mock_request.state.rbac_manager,
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_token.assert_called_once_with(user_id=f_kwargs['user_id'], data=mock_exc.return_value.dikt)
    assert isinstance(result, ConnexionResponse)
    assert result.content_type == 'text/plain' if raw else result.content_type == JSON_CONTENT_TYPE


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.generate_token', return_value='token')
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_login_user_ko(mock_token, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool):
    """Verify 'login_user' endpoint is handling WazuhException as expected."""
    mock_token.side_effect = WazuhException(999)
    result = await login_user(user='001', raw=mock_bool)
    f_kwargs = {'user_id': '001'}
    mock_dapi.assert_called_once_with(
        f=preprocessor.get_permissions,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        rbac_manager=ANY,
    )
    mock_exc.assert_has_calls([call(mock_dfunc.return_value), call(mock_token.side_effect)])
    assert mock_exc.call_count == 2
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize('raw', [True, False])
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.generate_token', return_value='token')
async def test_run_as_login(mock_token, mock_exc, mock_dapi, mock_remove, mock_dfunc, raw, mock_request):
    """Verify 'run_as_login' endpoint is working as expected."""
    result = await run_as_login(user='001', raw=raw)
    auth_context = await mock_request.json()
    f_kwargs = {'user_id': '001', 'auth_context': auth_context}
    mock_dapi.assert_called_once_with(
        f=preprocessor.get_permissions,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        rbac_manager=mock_request.state.rbac_manager,
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_token.assert_called_once_with(
        user_id=f_kwargs['user_id'], data=mock_exc.return_value.dikt, auth_context=auth_context
    )
    assert isinstance(result, ConnexionResponse)
    assert result.content_type == 'text/plain' if raw else result.content_type == JSON_CONTENT_TYPE


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.generate_token', return_value='token')
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_run_as_login_ko(mock_token, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool, mock_request):
    """Verify 'run_as_login' endpoint is handling WazuhException as expected."""
    mock_token.side_effect = WazuhException(999)
    result = await run_as_login(user='001', raw=mock_bool)
    f_kwargs = {'user_id': '001', 'auth_context': await mock_request.json()}
    mock_dapi.assert_called_once_with(
        f=preprocessor.get_permissions,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        rbac_manager=mock_request.state.rbac_manager,
    )
    mock_exc.assert_has_calls([call(mock_dfunc.return_value), call(mock_token.side_effect)])
    assert mock_exc.call_count == 2
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_user_me(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_user_me' endpoint is working as expected."""
    result = await get_user_me()
    f_kwargs = {}
    mock_dapi.assert_called_once_with(
        f=security.get_user_me,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=False,
        logger=ANY,
        wait_for_complete=False,
        current_user=mock_request.context['token_info']['sub'],
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
        rbac_manager=mock_request.state.rbac_manager,
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
async def test_get_user_me_policies(mock_request):
    """Verify 'get_user_me_policies' endpoint is working as expected."""
    with patch(
        'server_management_api.controllers.security_controller.WazuhResult', return_value='mock_wr_result'
    ) as mock_wr:
        result = await get_user_me_policies()
        mock_wr.assert_called_once_with(
            {
                'data': mock_request.context['token_info']['rbac_policies'],
                'message': 'Current user processed policies information was returned',
            }
        )
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_logout_user(mock_exc, mock_dapi, mock_dfunc, mock_request):
    """Verify 'logout_user' endpoint is working as expected."""
    result = await logout_user()
    mock_dapi.assert_called_once_with(
        f=security.revoke_current_user_tokens,
        request_type='local_master',
        is_async=False,
        logger=ANY,
        wait_for_complete=False,
        current_user=mock_request.context['token_info']['sub'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_users(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_users' endpoint is working as expected."""
    result = await get_users()
    f_kwargs = {
        'user_ids': None,
        'offset': 0,
        'limit': None,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'q': None,
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=security.get_users,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_edit_run_as(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'edit_run_as' endpoint is working as expected."""
    result = await edit_run_as(user_id='001', allow_run_as=False)
    f_kwargs = {'user_id': '001', 'allow_run_as': False}
    mock_dapi.assert_called_once_with(
        f=security.edit_run_as,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        current_user=mock_request.context['token_info']['sub'],
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_create_user(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'create_user' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.CreateUserModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await create_user()
            mock_dapi.assert_called_once_with(
                f=security.create_user,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_user(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'update_user' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.CreateUserModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await update_user(user_id='001')
            mock_dapi.assert_called_once_with(
                f=security.update_user,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_uids', ['001', 'all'])
async def test_delete_users(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_uids, mock_request):
    """Verify 'delete_users' endpoint is working as expected."""
    result = await delete_users(user_ids=mock_uids)
    if 'all' in mock_uids:
        mock_uids = None
    f_kwargs = {'user_ids': mock_uids}
    mock_dapi.assert_called_once_with(
        f=security.remove_users,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        current_user=mock_request.context['token_info']['sub'],
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_roles(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_roles' endpoint is working as expected."""
    result = await get_roles()
    f_kwargs = {
        'role_ids': None,
        'offset': 0,
        'limit': None,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'q': None,
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=security.get_roles,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_role(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'add_role' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.RoleModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await add_role()
            mock_dapi.assert_called_once_with(
                f=security.add_role,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_uids', ['001', 'all'])
async def test_remove_roles(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_uids, mock_request):
    """Verify 'remove_roles' endpoint is working as expected."""
    result = await remove_roles(role_ids=mock_uids)
    if 'all' in mock_uids:
        mock_uids = None
    f_kwargs = {'role_ids': mock_uids}
    mock_dapi.assert_called_once_with(
        f=security.remove_roles,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_role(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'update_role' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.RoleModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await update_role(role_id='001')
            mock_dapi.assert_called_once_with(
                f=security.update_role,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rules(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rules' endpoint is working as expected."""
    result = await get_rules()
    f_kwargs = {
        'rule_ids': None,
        'offset': 0,
        'limit': None,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'q': '',
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=security.get_rules,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_rule(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'add_rule' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.RuleModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await add_rule()
            mock_dapi.assert_called_once_with(
                f=security.add_rule,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_rule(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'update_rule' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.RuleModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await update_rule(rule_id='001')
            mock_dapi.assert_called_once_with(
                f=security.update_rule,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_rids', ['001', 'all'])
async def test_remove_rules(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_rids, mock_request):
    """Verify 'remove_rules' endpoint is working as expected."""
    result = await remove_rules(rule_ids=mock_rids)
    if 'all' in mock_rids:
        mock_rids = None
    f_kwargs = {'rule_ids': mock_rids}
    mock_dapi.assert_called_once_with(
        f=security.remove_rules,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_policies(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_policies' endpoint is working as expected."""
    result = await get_policies()
    f_kwargs = {
        'policy_ids': None,
        'offset': 0,
        'limit': None,
        'select': None,
        'sort_by': ['id'],
        'sort_ascending': True,
        'search_text': None,
        'complementary_search': None,
        'q': None,
        'distinct': False,
    }
    mock_dapi.assert_called_once_with(
        f=security.get_policies,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_policy(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'add_policy' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.PolicyModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await add_policy()
            mock_dapi.assert_called_once_with(
                f=security.add_policy,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_pids', ['001', 'all'])
async def test_remove_policies(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_pids, mock_request):
    """Verify 'remove_policies' endpoint is working as expected."""
    result = await remove_policies(policy_ids=mock_pids)
    if 'all' in mock_pids:
        mock_pids = None
    f_kwargs = {'policy_ids': mock_pids}
    mock_dapi.assert_called_once_with(
        f=security.remove_policies,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_policy(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'update_policy' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.PolicyModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:
            result = await update_policy(policy_id='001')
            mock_dapi.assert_called_once_with(
                f=security.update_policy,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_set_user_role(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'set_user_role' endpoint is working as expected."""
    result = await set_user_role(user_id='001', role_ids='001')
    f_kwargs = {'user_id': '001', 'role_ids': '001', 'position': None}
    mock_dapi.assert_called_once_with(
        f=security.set_user_role,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_rids', ['001', 'all'])
async def test_remove_user_role(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_rids, mock_request):
    """Verify 'remove_user_role' endpoint is working as expected."""
    result = await remove_user_role(user_id='001', role_ids=mock_rids)
    if 'all' in mock_rids:
        mock_rids = None
    f_kwargs = {'user_id': '001', 'role_ids': mock_rids}
    mock_dapi.assert_called_once_with(
        f=security.remove_user_role,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_set_role_policy(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'set_role_policy' endpoint is working as expected."""
    result = await set_role_policy(role_id='001', policy_ids='001')
    f_kwargs = {'role_id': '001', 'policy_ids': '001', 'position': None}
    mock_dapi.assert_called_once_with(
        f=security.set_role_policy,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_rids', ['001', 'all'])
async def test_remove_role_policy(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_rids, mock_request):
    """Verify 'remove_role_policy' endpoint is working as expected."""
    result = await remove_role_policy(role_id='001', policy_ids=mock_rids)
    if 'all' in mock_rids:
        mock_rids = None
    f_kwargs = {'role_id': '001', 'policy_ids': mock_rids}
    mock_dapi.assert_called_once_with(
        f=security.remove_role_policy,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_set_role_rule(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'set_role_rule' endpoint is working as expected."""
    result = await set_role_rule(role_id='001', rule_ids='001')
    f_kwargs = {
        'role_id': '001',
        'rule_ids': '001',
        'run_as': {
            'user': mock_request.context['token_info']['sub'],
            'run_as': mock_request.context['token_info']['run_as'],
        },
    }
    mock_dapi.assert_called_once_with(
        f=security.set_role_rule,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_rids', ['001', 'all'])
async def test_remove_role_rule(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_rids, mock_request):
    """Verify 'remove_role_rule' endpoint is working as expected."""
    result = await remove_role_rule(role_id='001', rule_ids=mock_rids)
    if 'all' in mock_rids:
        mock_rids = None
    f_kwargs = {'role_id': '001', 'rule_ids': mock_rids}
    mock_dapi.assert_called_once_with(
        f=security.remove_role_rule,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rbac_resources(mock_exc, mock_dapi, mock_remove, mock_dfunc):
    """Verify 'get_rbac_resources' endpoint is working as expected."""
    result = await get_rbac_resources()
    f_kwargs = {'resource': None}
    mock_dapi.assert_called_once_with(
        f=security.get_rbac_resources,
        f_kwargs=mock_remove.return_value,
        request_type='local_any',
        is_async=False,
        logger=ANY,
        wait_for_complete=True,
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rbac_actions(mock_exc, mock_dapi, mock_remove, mock_dfunc):
    """Verify 'get_rbac_actions' endpoint is working as expected."""
    result = await get_rbac_actions()
    f_kwargs = {'endpoint': None}
    mock_dapi.assert_called_once_with(
        f=security.get_rbac_actions,
        f_kwargs=mock_remove.return_value,
        request_type='local_any',
        is_async=False,
        logger=ANY,
        wait_for_complete=True,
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.isinstance')
@pytest.mark.parametrize('mock_snodes', [None, AsyncMock()])
async def test_revoke_all_tokens(mock_isins, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_snodes, mock_request):
    """Verify 'revoke_all_tokens' endpoint is working as expected."""
    mock_isins.return_value = True if not mock_snodes else False
    with patch('server_management_api.controllers.security_controller.get_system_nodes', return_value=mock_snodes):
        result = await revoke_all_tokens()
        if not mock_snodes:
            mock_isins.assert_called_once()
        mock_dapi.assert_called_once_with(
            f=security.wrapper_revoke_tokens,
            f_kwargs=mock_remove.return_value,
            request_type='distributed_master' if mock_snodes is not None else 'local_any',
            is_async=True,
            broadcasting=mock_snodes is not None,
            logger=ANY,
            wait_for_complete=True,
            rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            nodes=mock_snodes,
        )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        mock_remove.assert_called_once_with({})
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.type', return_value=AffectedItemsWazuhResult)
@patch('server_management_api.controllers.security_controller.len', return_value=0)
async def test_revoke_all_tokens_ko(mock_type, mock_len, mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'revoke_all_tokens' endpoint is handling WazuhPermissionError as expected."""
    with patch(
        'server_management_api.controllers.security_controller.get_system_nodes', return_value=AsyncMock()
    ) as mock_snodes:
        result = await revoke_all_tokens()
        mock_dapi.assert_called_once_with(
            f=security.wrapper_revoke_tokens,
            f_kwargs=mock_remove.return_value,
            request_type='distributed_master',
            is_async=True,
            broadcasting=True,
            logger=ANY,
            wait_for_complete=True,
            rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            nodes=mock_snodes.return_value,
        )
        mock_exc.assert_has_calls(
            [call(mock_dfunc.return_value), call(WazuhPermissionError(4000, mock_exc.return_value.message))]
        )
        assert mock_exc.call_count == 2
        mock_remove.assert_called_once_with({})
        assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_security_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_security_config' endpoint is working as expected."""
    result = await get_security_config()
    mock_dapi.assert_called_once_with(
        f=security.get_security_config,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        logger=ANY,
        wait_for_complete=False,
        rbac_permissions=mock_request.context['token_info']['rbac_policies'],
    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with({})
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('server_management_api.controllers.security_controller.isinstance')
@pytest.mark.parametrize('mock_snodes', [None, AsyncMock()])
async def test_security_revoke_tokens(mock_isins, mock_exc, mock_dapi, mock_dfunc, mock_snodes):
    """Verify 'security_revoke_tokens' endpoint is working as expected."""
    mock_isins.return_value = True if not mock_snodes else False
    with patch('server_management_api.controllers.security_controller.get_system_nodes', return_value=mock_snodes):
        await security_revoke_tokens()
        mock_dapi.assert_called_once_with(
            f=security.revoke_tokens,
            request_type='distributed_master' if mock_snodes is not None else 'local_any',
            is_async=True,
            wait_for_complete=True,
            broadcasting=mock_snodes is not None,
            logger=ANY,
            nodes=mock_snodes,
        )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_security_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_security_config' endpoint is working as expected."""
    with patch('server_management_api.controllers.security_controller.Body.validate_content_type'):
        with patch(
            'server_management_api.controllers.security_controller.SecurityConfigurationModel.get_kwargs',
            return_value=AsyncMock(),
        ) as mock_getkwargs:
            with patch(
                'server_management_api.controllers.security_controller.security_revoke_tokens', return_value=AsyncMock()
            ):
                result = await put_security_config()
                f_kwargs = {'updated_config': mock_getkwargs.return_value}
                mock_dapi.assert_called_once_with(
                    f=security.update_security_config,
                    f_kwargs=mock_remove.return_value,
                    request_type='local_master',
                    is_async=True,
                    logger=ANY,
                    wait_for_complete=False,
                    rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                )
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                mock_remove.assert_called_once_with(f_kwargs)
                assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch(
    'server_management_api.controllers.security_controller.DistributedAPI.distribute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.security_controller.remove_nones_to_dict')
@patch('server_management_api.controllers.security_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.security_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_security_config(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_security_config' endpoint is working as expected."""
    with patch(
        'server_management_api.controllers.security_controller.SecurityConfigurationModel.get_kwargs',
        return_value=AsyncMock(),
    ) as mock_getkwargs:
        with patch(
            'server_management_api.controllers.security_controller.security_revoke_tokens', return_value=AsyncMock()
        ):
            result = await delete_security_config()
            f_kwargs = {'updated_config': mock_getkwargs.return_value}
            mock_dapi.assert_called_once_with(
                f=security.update_security_config,
                f_kwargs=mock_remove.return_value,
                request_type='local_master',
                is_async=True,
                logger=ANY,
                wait_for_complete=False,
                rbac_permissions=mock_request.context['token_info']['rbac_policies'],
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, ConnexionResponse)
