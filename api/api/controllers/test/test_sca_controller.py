import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.sca_controller import (get_sca_agent,
                                                    get_sca_checks)
        from api.controllers.test.utils import CustomMagicMockReturn
        from wazuh import sca
        from wazuh.core.common import database_limit
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.sca_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.sca_controller.remove_nones_to_dict')
@patch('api.controllers.sca_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.sca_controller.raise_if_exc', return_value=CustomMagicMockReturn())
async def test_sca_controller(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request=MagicMock()):
    """Test all sca_controller endpoints"""
    async def test_get_sca_agent():
        filters = {'name': None,
                   'description': None,
                   'references': None
                   }
        f_kwargs = {'agent_list': [None],
                    'offset': 0,
                    'limit': database_limit,
                    'sort': None,
                    'search': None,
                    'q': None,
                    'filters': filters
                    }
        result = await get_sca_agent(request=mock_request)
        mock_dapi.assert_called_with(f=sca.get_sca_list,
                                     f_kwargs=mock_remove.return_value,
                                     request_type='distributed_master',
                                     is_async=False,
                                     wait_for_complete=False,
                                     logger=ANY,
                                     rbac_permissions=mock_request['token_info']['rbac_policies']
                                     )
        mock_exc.assert_called_with(mock_dfunc.return_value)
        mock_remove.assert_called_with(f_kwargs)
        assert isinstance(result, web_response.Response)

    async def test_get_sca_checks():
        filters = {'title': None,
                   'description': None,
                   'rationale': None,
                   'remediation': None,
                   'command': None,
                   'status': None,
                   'reason': None,
                   'file': None,
                   'process': None,
                   'directory': None,
                   'registry': None,
                   'references': None,
                   'result': None,
                   'condition': None
                   }
        f_kwargs = {'policy_id': None,
                    'agent_list': [None],
                    'offset': 0,
                    'limit': database_limit,
                    'sort': None,
                    'search': None,
                    'q': None,
                    'filters': filters
                    }
        result = await get_sca_checks(request=mock_request)
        mock_dapi.assert_called_with(f=sca.get_sca_checks,
                                     f_kwargs=mock_remove.return_value,
                                     request_type='distributed_master',
                                     is_async=False,
                                     wait_for_complete=False,
                                     logger=ANY,
                                     rbac_permissions=mock_request['token_info']['rbac_policies'])
        mock_exc.assert_called_with(mock_dfunc.return_value)
        mock_remove.assert_called_with(f_kwargs)
        assert isinstance(result, web_response.Response)

    # Function list containing all sub tests declared above.
    functions = [test_get_sca_agent,
                 test_get_sca_checks
                 ]
    for test_funct in functions:
        await test_funct()
