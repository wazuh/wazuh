import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from aiohttp import web_response
from api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.engine_controller import add_catalog_resource, get_catalog_resource, \
            update_catalog_resource, delete_catalog_resource, validate_catalog_resource
        from wazuh import engine as engine_framework
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.engine_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.engine_controller.remove_nones_to_dict')
@patch('api.controllers.engine_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.engine_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_add_catalog_resource(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify that the add_catalog_resource endpoint is working as expected."""
    with patch('api.controllers.engine_controller.Body.validate_content_type'):
        with patch('api.models.engine_model.AddCatalogResourceModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await add_catalog_resource(request=mock_request)
            mock_dapi.assert_called_once_with(f=engine_framework.add_catalog_resource,
                                            f_kwargs=mock_remove.return_value,
                                            request_type='local_master',
                                            is_async=False,
                                            wait_for_complete=False,
                                            logger=ANY,
                                            rbac_permissions=mock_request['token_info']['rbac_policies']
                                            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, web_response.Response)

@pytest.mark.asyncio
@patch('api.controllers.engine_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.engine_controller.remove_nones_to_dict')
@patch('api.controllers.engine_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.engine_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_catalog_resource(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify that the get_catalog_resource endpoint is working as expected."""
    result = await get_catalog_resource(request=mock_request)
    f_kwargs = {'name': None, 'resource_type': None}
    mock_dapi.assert_called_once_with(f=engine_framework.get_catalog_resource,
                                    f_kwargs=mock_remove.return_value,
                                    request_type='local_master',
                                    is_async=False,
                                    wait_for_complete=False,
                                    logger=ANY,
                                    rbac_permissions=mock_request['token_info']['rbac_policies']
                                    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)

@pytest.mark.asyncio
@patch('api.controllers.engine_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.engine_controller.remove_nones_to_dict')
@patch('api.controllers.engine_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.engine_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_update_catalog_resource(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify that the update_catalog_resource endpoint is working as expected."""
    with patch('api.controllers.engine_controller.Body.validate_content_type'):
        with patch('api.models.engine_model.UpdateCatalogResourceModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await update_catalog_resource(request=mock_request)
            mock_dapi.assert_called_once_with(f=engine_framework.update_catalog_resource,
                                            f_kwargs=mock_remove.return_value,
                                            request_type='local_master',
                                            is_async=False,
                                            wait_for_complete=False,
                                            logger=ANY,
                                            rbac_permissions=mock_request['token_info']['rbac_policies']
                                            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, web_response.Response)

@pytest.mark.asyncio
@patch('api.controllers.engine_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.engine_controller.remove_nones_to_dict')
@patch('api.controllers.engine_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.engine_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_catalog_resource(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify that the delete_catalog_resource endpoint is working as expected."""
    result = await delete_catalog_resource(request=mock_request)
    f_kwargs = {'name': None}
    mock_dapi.assert_called_once_with(f=engine_framework.delete_catalog_resource,
                                    f_kwargs=mock_remove.return_value,
                                    request_type='local_master',
                                    is_async=False,
                                    wait_for_complete=False,
                                    logger=ANY,
                                    rbac_permissions=mock_request['token_info']['rbac_policies']
                                    )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, web_response.Response)

@pytest.mark.asyncio
@patch('api.controllers.engine_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.engine_controller.remove_nones_to_dict')
@patch('api.controllers.engine_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.engine_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_validate_catalog_resource(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Verify that the validate_catalog_resource endpoint is working as expected."""
    with patch('api.controllers.engine_controller.Body.validate_content_type'):
        with patch('api.models.engine_model.UpdateCatalogResourceModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await validate_catalog_resource(request=mock_request)
            mock_dapi.assert_called_once_with(f=engine_framework.validate_catalog_resource,
                                            f_kwargs=mock_remove.return_value,
                                            request_type='local_master',
                                            is_async=False,
                                            wait_for_complete=False,
                                            logger=ANY,
                                            rbac_permissions=mock_request['token_info']['rbac_policies']
                                            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, web_response.Response)
