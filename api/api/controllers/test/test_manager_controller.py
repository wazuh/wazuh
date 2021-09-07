import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.manager_controller import (get_status,
                                                        get_info,
                                                        get_configuration,
                                                        get_stats,
                                                        get_stats_hourly,
                                                        get_stats_weekly,
                                                        get_stats_analysisd,
                                                        get_stats_remoted,
                                                        get_log,
                                                        get_log_summary,
                                                        get_api_config,
                                                        put_restart,
                                                        get_conf_validation,
                                                        get_manager_config_ondemand,
                                                        update_configuration)
        from wazuh import manager
        import wazuh.stats as stats
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
@pytest.mark.parametrize('mock_bool', [(True), (False)])
async def test_manager_controller(mock_request, mock_bool):
    async def test_get_status():
        calls = [call(f=manager.get_status,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_status(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_info():
        calls = [call(f=manager.get_basic_info,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_info(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_configuration(mock_bool):
        with patch('api.controllers.manager_controller.isinstance', return_value=mock_bool) as mock_isinstance:
            calls = [call(f=manager.read_ossec_conf,
                          f_kwargs=ANY,
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=False,
                          logger=ANY,
                          rbac_permissions=mock_request['token_info']['rbac_policies']
                          )
                     ]
            result = await get_configuration(mock_request)
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            if mock_isinstance.return_value:
                assert isinstance(result, web_response.Response)
            else:
                assert isinstance(result, ConnexionResponse)

    async def test_get_stats():
        calls = [call(f=stats.totals,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_stats(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_stats_hourly():
        calls = [call(f=stats.hourly,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_stats_hourly(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_stats_weekly():
        calls = [call(f=stats.weekly,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_stats_weekly(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_stats_analysisd():
        calls = [call(f=stats.get_daemons_stats,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_stats_analysisd(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_stats_remoted():
        calls = [call(f=stats.get_daemons_stats,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_stats_remoted(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_log():
        calls = [call(f=manager.ossec_log,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_log(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_log_summary():
        calls = [call(f=manager.ossec_log_summary,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_log_summary(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_api_config():
        calls = [call(f=manager.get_api_config,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_api_config(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_put_restart():
        calls = [call(f=manager.restart,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_restart(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_conf_validation():
        calls = [call(f=manager.validation,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_conf_validation(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_manager_config_ondemand():
        calls = [call(f=manager.get_config,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_manager_config_ondemand(mock_request,
                                                   component='component1')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_update_configuration():
        with patch('api.controllers.manager_controller.Body.validate_content_type'):
            with patch('api.controllers.manager_controller.Body.decode_body', return_value={}):
                calls = [call(f=manager.update_ossec_conf,
                              f_kwargs=ANY,
                              request_type='local_any',
                              is_async=False,
                              wait_for_complete=False,
                              logger=ANY,
                              rbac_permissions=mock_request['token_info']['rbac_policies']
                              )
                         ]
                result = await update_configuration(mock_request,
                                                    body={})
                mock_dapi.assert_has_calls(calls)
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                assert isinstance(result, web_response.Response)

    functions = [test_get_status(),
                 test_get_info(),
                 test_get_configuration(mock_bool),
                 test_get_stats(),
                 test_get_stats_hourly(),
                 test_get_stats_weekly(),
                 test_get_stats_analysisd(),
                 test_get_stats_remoted(),
                 test_get_log(),
                 test_get_log_summary(),
                 test_get_api_config(),
                 test_put_restart(),
                 test_get_conf_validation(),
                 test_get_manager_config_ondemand(),
                 test_update_configuration()
                 ]
    for test_funct in functions:
        with patch('api.controllers.manager_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.manager_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.manager_controller.raise_if_exc',
                           return_value={'message': 'value1'}) as mock_exc:
                    await test_funct
