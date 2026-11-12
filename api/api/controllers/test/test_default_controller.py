# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.default_controller import (BasicInfo, DATE_FORMAT,
                                                        default_info, socket)
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


FIXED_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.mark.asyncio
@patch('api.controllers.default_controller.get_utc_now', return_value=FIXED_NOW)
@patch('api.controllers.default_controller.load_spec', return_value=MagicMock())
@patch('api.controllers.default_controller.WazuhResult', return_value={})
async def test_default_info(mock_wresult, mock_lspec, mock_now):
    """Verify 'default_info' endpoint is working as expected.

    The clock is fixed: the controller and the test each read it, and a second boundary between the two
    reads made the timestamps differ.
    """
    result = await default_info()
    data = {
        'title': mock_lspec.return_value['info']['title'],
        'api_version': mock_lspec.return_value['info']['version'],
        'revision': mock_lspec.return_value['info']['x-revision'],
        'license_name': mock_lspec.return_value['info']['license']['name'],
        'license_url': mock_lspec.return_value['info']['license']['url'],
        'hostname': socket.gethostname(),
        'timestamp': FIXED_NOW.strftime(DATE_FORMAT)
    }
    mock_lspec.assert_called_once_with()
    mock_wresult.assert_called_once_with({'data': BasicInfo.from_dict(data)})
    assert isinstance(result, ConnexionResponse)
