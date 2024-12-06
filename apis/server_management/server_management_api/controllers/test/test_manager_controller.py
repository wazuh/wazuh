# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from server_management_api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from server_management_api.controllers.test.utils import CustomAffectedItems


with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from server_management_api.controllers.manager_controller import check_available_version
        from wazuh import manager
        from wazuh.core.manager import query_update_check_service
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.parametrize(
        "force_query,dapi_call_count,update_check", ([True, 2, True], [True, 1, False], [False, 1, True])
)
@pytest.mark.asyncio
@patch('server_management_api.controllers.manager_controller.configuration.update_check_is_enabled')
@patch('server_management_api.controllers.manager_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('server_management_api.controllers.manager_controller.DistributedAPI.__init__', return_value=None)
@patch('server_management_api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_check_available_version(
    mock_exc,
    mock_dapi,
    mock_dfunc,
    update_check_mock,
    force_query,
    dapi_call_count,
    update_check,
):
    """Verify 'check_available_version' endpoint is working as expected."""
    cti_context = {UPDATE_INFORMATION_KEY: {"foo": 1}, INSTALLATION_UID_KEY: "1234"}
    update_check_mock.return_value = update_check

    with patch('server_management_api.controllers.manager_controller.cti_context', new=cti_context):
        result = await check_available_version(force_query=force_query)
        assert mock_dapi.call_count == dapi_call_count

        if force_query and update_check:
            mock_dapi.assert_any_call(
                f=query_update_check_service,
                f_kwargs={INSTALLATION_UID_KEY: cti_context[INSTALLATION_UID_KEY]},
                request_type='local_master',
                is_async=True,
                logger=ANY,
            )
            mock_exc.assert_any_call(mock_dfunc.return_value)

        mock_dapi.assert_called_with(
            f=manager.get_update_information,
            f_kwargs={INSTALLATION_UID_KEY: cti_context[INSTALLATION_UID_KEY],
                      UPDATE_INFORMATION_KEY: cti_context[UPDATE_INFORMATION_KEY]},
            request_type='local_master',
            is_async=False,
            logger=ANY,
        )
        mock_exc.assert_called_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)
