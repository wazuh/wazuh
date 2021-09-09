import sys
from unittest.mock import ANY, MagicMock, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.default_controller import default_info
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
async def test_default_controller():
    """Test all default_controller endpoints"""
    async def test_default_info():
        result = await default_info()
        mock_lspec.assert_called_once_with()
        mock_wresult.assert_called_once_with({'data': ANY})
        assert isinstance(result, web_response.Response)

    # Function list containing all sub tests declared above.
    functions = [test_default_info()
                 ]
    for test_funct in functions:
        with patch('api.controllers.default_controller.load_spec') as mock_lspec:
            with patch('api.controllers.default_controller.WazuhResult', return_value={}) as mock_wresult:
                await test_funct
