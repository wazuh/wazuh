# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from connexion.testing import TestContext
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin

from server_management_api.controllers.test.utils import CustomAffectedItems, get_default_configuration
from server_management_api.controllers.util import JSON_CONTENT_TYPE

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            import wazuh.rbac.decorators
            from wazuh.core.exception import WazuhException
            from wazuh.rbac import preprocessor
            from wazuh.tests.util import RBAC_bypasser

            from server_management_api.controllers.security_controller import (
                login_user,
                run_as_login,
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
    'server_management_api.controllers.security_controller.DistributedAPI.execute_function', return_value=AsyncMock()
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
    'server_management_api.controllers.security_controller.DistributedAPI.execute_function', return_value=AsyncMock()
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
    'server_management_api.controllers.security_controller.DistributedAPI.execute_function', return_value=AsyncMock()
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
    'server_management_api.controllers.security_controller.DistributedAPI.execute_function', return_value=AsyncMock()
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
        is_async=True,
        logger=ANY,
        rbac_manager=mock_request.state.rbac_manager,
    )
    mock_exc.assert_has_calls([call(mock_dfunc.return_value), call(mock_token.side_effect)])
    assert mock_exc.call_count == 2
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
