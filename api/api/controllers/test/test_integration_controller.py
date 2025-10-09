# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.integration_controller import (
            create_integration,
            get_integrations,
            update_integration,
            delete_integration
        )
        from wazuh import integration as integration_framework
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']

TEST_INTEGRATION_BODY = {
    'type': 'integration',
    'id': 'int1',
    'name': 'Integration 1',
    'documentation': 'doc',
    'description': 'desc',
    'status': 'enabled',
    'kvdbs': [],
    'decoders': []
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch('api.controllers.integration_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.integration_controller.remove_nones_to_dict')
@patch('api.controllers.integration_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.integration_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('api.controllers.integration_controller.Body.validate_content_type')
@patch('api.controllers.integration_controller.IntegrationCreateModel')
@patch('api.controllers.integration_controller.Integration', return_value=MagicMock())
async def test_create_integration(mock_integration_model, mock_create_model_cls, mock_validate, mock_exc, mock_dapi,
                                  mock_remove, mock_dfunc, mock_request):
    """Verify 'create_integration' works as expected."""
    mock_instance = MagicMock()
    mock_instance.type = TEST_INTEGRATION_BODY['type']
    mock_instance.id = TEST_INTEGRATION_BODY['id']
    mock_instance.name = TEST_INTEGRATION_BODY['name']
    mock_instance.documentation = TEST_INTEGRATION_BODY['documentation']
    mock_instance.description = TEST_INTEGRATION_BODY['description']
    mock_instance.status = TEST_INTEGRATION_BODY['status']
    mock_instance.kvdbs = TEST_INTEGRATION_BODY['kvdbs']
    mock_instance.decoders = TEST_INTEGRATION_BODY['decoders']
    mock_create_model_cls.return_value = mock_instance

    result = await create_integration(body=TEST_INTEGRATION_BODY, type_='policy')
    f_kwargs = {
        'integration': mock_integration_model.return_value,
        'policy_type': 'policy'
    }
    mock_dapi.assert_called_once_with(
        f=integration_framework.create_integration,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch('api.controllers.integration_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.integration_controller.remove_nones_to_dict')
@patch('api.controllers.integration_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.integration_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_integrations(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_integrations' works as expected."""
    result = await get_integrations(type_='policy', integrations_list=['a', 'b'])
    f_kwargs = {
        'policy_type': 'policy',
        'names': ['a', 'b'],
        'status': None,
        'search': None
    }
    mock_dapi.assert_called_once_with(
        f=integration_framework.get_integrations,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch('api.controllers.integration_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.integration_controller.remove_nones_to_dict')
@patch('api.controllers.integration_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.integration_controller.raise_if_exc', return_value=CustomAffectedItems())
@patch('api.controllers.integration_controller.Body.validate_content_type')
@patch('api.controllers.integration_controller.IntegrationCreateModel')
@patch('api.controllers.integration_controller.Integration', return_value=MagicMock())
async def test_update_integration(mock_integration_model, mock_create_model_cls, mock_validate, mock_exc, mock_dapi,
                                  mock_remove, mock_dfunc, mock_request):
    """Verify 'update_integration' works as expected."""
    mock_instance = MagicMock()
    mock_instance.type = TEST_INTEGRATION_BODY['type']
    mock_instance.id = TEST_INTEGRATION_BODY['id']
    mock_instance.name = TEST_INTEGRATION_BODY['name']
    mock_instance.documentation = TEST_INTEGRATION_BODY['documentation']
    mock_instance.description = TEST_INTEGRATION_BODY['description']
    mock_instance.status = TEST_INTEGRATION_BODY['status']
    mock_instance.kvdbs = TEST_INTEGRATION_BODY['kvdbs']
    mock_instance.decoders = TEST_INTEGRATION_BODY['decoders']
    mock_create_model_cls.return_value = mock_instance

    result = await update_integration(body=TEST_INTEGRATION_BODY, type_='policy')
    f_kwargs = {
        'integration': mock_integration_model.return_value,
        'policy_type': 'policy'
    }
    mock_dapi.assert_called_once_with(
        f=integration_framework.update_integration,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["integration_controller"], indirect=True)
@patch('api.controllers.integration_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.integration_controller.remove_nones_to_dict')
@patch('api.controllers.integration_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.integration_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_integration(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_integration' works as expected."""
    result = await delete_integration(type_='policy', integrations_list=['x'])
    f_kwargs = {
        'policy_type': 'policy',
        'names': ['x']
    }
    mock_dapi.assert_called_once_with(
        f=integration_framework.delete_integration,
        f_kwargs=mock_remove.return_value,
        request_type='local_master',
        is_async=True,
        wait_for_complete=False,
        logger=ANY,
        rbac_permissions=mock_request.context['token_info']['rbac_policies']
    )
    mock_remove.assert_called_once_with(f_kwargs)
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)
