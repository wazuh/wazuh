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
        from api.controllers.analysisd_controller import put_reload_analysisd
        from wazuh import analysisd
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']

@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["analysisd_controller"], indirect=True)
@patch('api.controllers.analysisd_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.analysisd_controller.remove_nones_to_dict')
@patch('api.controllers.analysisd_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.analysisd_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_reload_analysisd(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_reload_analysisd' endpoint is working as expected."""
    with patch('api.controllers.analysisd_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
        result = await put_reload_analysisd()
        f_kwargs = {'node_list': '*'}
        mock_dapi.assert_called_once_with(f=analysisd.reload_ruleset,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='distributed_master',
                                          is_async=True,
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
