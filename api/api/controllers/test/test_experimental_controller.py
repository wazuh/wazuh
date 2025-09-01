# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems
from wazuh.core.exception import WazuhResourceNotFound

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.experimental_controller import (
            check_experimental_feature_value, get_cis_cat_results)
        from wazuh import ciscat
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["experimental_controller"], indirect=True)
@patch('api.configuration.api_conf')
@patch('api.controllers.experimental_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.experimental_controller.remove_nones_to_dict')
@patch('api.controllers.experimental_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.experimental_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_cis_cat_results(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp, mock_request):
    """Verify 'get_cis_cat_results' endpoint is working as expected."""
    result = await get_cis_cat_results()
    f_kwargs = {'agent_list': '*',
                'offset': 0,
                'limit': None,
                'select': None,
                'sort': None,
                'search': None,
                'filters': {
                    'benchmark': None,
                    'profile': None,
                    'fail': None,
                    'error': None,
                    'notchecked': None,
                    'unknown': None,
                    'score': None,
                    'pass': mock_request.query_params.get('pass', None)
                    }
                }
    mock_dapi.assert_called_once_with(f=ciscat.get_ciscat_results,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=True,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@patch('api.controllers.experimental_controller.raise_if_exc')
async def test_check_experimental_feature_value(mock_exc):
    @check_experimental_feature_value
    async def func_():
        pass
    with patch('api.configuration.api_conf', new={'experimental_features': False}):
        await func_()
        mock_exc.assert_called_once_with(WazuhResourceNotFound(1122))
    with patch('api.configuration.api_conf', new={'experimental_features': True}):
        await func_()
