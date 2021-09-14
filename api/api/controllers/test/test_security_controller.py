import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.test.utils import CustomMagicMockReturn
        from api.controllers.security_controller import (add_policy,
                                                         add_role,
                                                         add_rule,
                                                         create_user,
                                                         delete_security_config,
                                                         delete_users,
                                                         edit_run_as,
                                                         get_policies,
                                                         get_rbac_actions,
                                                         get_rbac_resources,
                                                         get_roles,
                                                         get_rules,
                                                         get_security_config,
                                                         get_user_me,
                                                         get_user_me_policies,
                                                         get_users,
                                                         login_user,
                                                         logout_user,
                                                         put_security_config,
                                                         remove_policies,
                                                         remove_role_policy,
                                                         remove_role_rule,
                                                         remove_roles,
                                                         remove_rules,
                                                         remove_user_role,
                                                         revoke_all_tokens,
                                                         run_as_login,
                                                         security_revoke_tokens,
                                                         set_role_policy,
                                                         set_role_rule,
                                                         set_user_role,
                                                         update_policy,
                                                         update_role,
                                                         update_rule,
                                                         update_user)
        from wazuh import security
        from wazuh.core.exception import WazuhException
        from wazuh.rbac import preprocessor
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request, mock_user, mock_bool', [
    (MagicMock(), 'user1', True),
    (MagicMock(), 'user1', False)
    ])
async def test_security_controller(mock_request, mock_user, mock_bool):
    """Test all security_controller endpoints"""
    async def test_login_user():
        calls = [call(f=preprocessor.get_permissions,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY
                      )
                 ]
        result = await login_user(user=mock_user,
                                  raw=mock_bool)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_login_user_raise():
        calls = [call(f=preprocessor.get_permissions,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY
                      )
                 ]
        mock_token.side_effect = WazuhException(999)
        result = await login_user(user=mock_user,
                                  raw=mock_bool)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_has_calls([call(mock_dfunc.return_value),
                                   call(mock_token.side_effect)])
        assert isinstance(result, web_response.Response)

    async def test_run_as_login():
        calls = [call(f=preprocessor.get_permissions,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY
                      )
                 ]
        result = await run_as_login(request=AsyncMock(),
                                    user=mock_user,
                                    raw=mock_bool)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_run_as_login_raise():
        calls = [call(f=preprocessor.get_permissions,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY
                      )
                 ]
        mock_token.side_effect = WazuhException(999)
        result = await run_as_login(request=AsyncMock(),
                                    user=mock_user,
                                    raw=mock_bool)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_has_calls([call(mock_dfunc.return_value),
                                   call(mock_token.side_effect)])
        assert isinstance(result, web_response.Response)

    async def test_get_user_me():
        calls = [call(f=security.get_user_me,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      current_user=mock_request['token_info']['sub'],
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_user_me(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_user_me_policies():
        with patch('api.controllers.security_controller.WazuhResult', return_value='mock_wr_result') as mock_wr:
            result = await get_user_me_policies(request=mock_request)
            mock_wr.assert_called_with({'data': mock_request['token_info']['rbac_policies'],
                                        'message': "Current user processed policies information was returned"})
        assert isinstance(result, web_response.Response)

    async def test_logout_user():
        calls = [call(f=security.revoke_current_user_tokens,
                      request_type='local_master',
                      is_async=False,
                      current_user=mock_request['token_info']['sub'],
                      wait_for_complete=False,
                      logger=ANY
                      )
                 ]
        result = await logout_user(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_users():
        calls = [call(f=security.get_users,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_users(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_edit_run_as():
        calls = [call(f=security.edit_run_as,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      current_user=mock_request['token_info']['sub'],
                      rbac_permissions=mock_request['token_info']['rbac_policies'],
                      wait_for_complete=False
                      )
                 ]
        result = await edit_run_as(request=mock_request,
                                   user_id=mock_user,
                                   allow_run_as=mock_bool)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_create_user():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.CreateUserModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.create_user,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await create_user(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_update_user():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.CreateUserModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.update_user,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await update_user(request=mock_request,
                                               user_id='001')
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_delete_users():
        calls = [call(f=security.remove_users,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      current_user=mock_request['token_info']['sub'],
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_users(request=mock_request,
                                    user_ids='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_roles():
        calls = [call(f=security.get_roles,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_roles(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_add_role():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.RoleModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.add_role,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await add_role(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_remove_roles():
        calls = [call(f=security.remove_roles,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_roles(request=mock_request,
                                    role_ids='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_update_role():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.RoleModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.update_role,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await update_role(request=mock_request,
                                               role_id='001')
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_get_rules():
        calls = [call(f=security.get_rules,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rules(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_add_rule():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.RuleModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.add_rule,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await add_rule(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_update_rule():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.RuleModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.update_rule,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await update_rule(request=mock_request,
                                               rule_id='001')
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_remove_rules():
        calls = [call(f=security.remove_rules,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_rules(request=mock_request,
                                    rule_ids='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_policies():
        calls = [call(f=security.get_policies,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_policies(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_add_policy():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.PolicyModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.add_policy,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await add_policy(request=mock_request)
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_remove_policies():
        calls = [call(f=security.remove_policies,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_policies(request=mock_request,
                                       policy_ids='all')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_update_policy():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.PolicyModel.get_kwargs', return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    calls = [call(f=security.update_policy,
                                  f_kwargs=ANY,
                                  request_type='local_master',
                                  is_async=False,
                                  logger=ANY,
                                  rbac_permissions=mock_request['token_info']['rbac_policies'],
                                  wait_for_complete=False
                                  )
                             ]
                    result = await update_policy(request=mock_request,
                                                 policy_id='001')
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once_with(mock_dfunc.return_value)
                    assert isinstance(result, web_response.Response)

    async def test_set_user_role():
        calls = [call(f=security.set_user_role,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await set_user_role(request=mock_request,
                                     user_id='001',
                                     role_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_remove_user_role():
        calls = [call(f=security.remove_user_role,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_user_role(request=mock_request,
                                        user_id='001',
                                        role_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_set_role_policy():
        calls = [call(f=security.set_role_policy,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await set_role_policy(request=mock_request,
                                       role_id='001',
                                       policy_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_remove_role_policy():
        calls = [call(f=security.remove_role_policy,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_role_policy(request=mock_request,
                                          role_id='001',
                                          policy_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_set_role_rule():
        calls = [call(f=security.set_role_rule,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await set_role_rule(request=mock_request,
                                     role_id='001',
                                     rule_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_remove_role_rule():
        calls = [call(f=security.remove_role_rule,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await remove_role_rule(request=mock_request,
                                        role_id='001',
                                        rule_ids='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rbac_resources():
        calls = [call(f=security.get_rbac_resources,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=True
                      )
                 ]
        result = await get_rbac_resources()
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rbac_actions():
        calls = [call(f=security.get_rbac_actions,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=True
                      )
                 ]
        result = await get_rbac_actions()
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_revoke_all_tokens():
        with patch('api.controllers.security_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
            calls = [call(f=security.wrapper_revoke_tokens,
                          f_kwargs=ANY,
                          request_type='distributed_master',
                          is_async=False,
                          broadcasting=True,
                          wait_for_complete=True,
                          logger=ANY,
                          rbac_permissions=mock_request['token_info']['rbac_policies'],
                          nodes=mock_snodes.return_value
                          )
                     ]
            result = await revoke_all_tokens(request=mock_request)
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            assert isinstance(result, web_response.Response)

    async def test_get_security_config():
        calls = [call(f=security.get_security_config,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY,
                      wait_for_complete=False,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_security_config(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_security_revoke_tokens():
        with patch('api.controllers.security_controller.get_system_nodes', return_value=AsyncMock()) as mock_snodes:
            calls = [call(f=security.revoke_tokens,
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=True,
                          broadcasting=True,
                          logger=ANY,
                          nodes=mock_snodes.return_value
                          )
                     ]
            await security_revoke_tokens()
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once_with(mock_dfunc.return_value)

    async def test_put_security_config():
        with patch('api.controllers.security_controller.Body.validate_content_type'):
            with patch('api.controllers.security_controller.SecurityConfigurationModel.get_kwargs',
                       return_value=AsyncMock()):
                with patch('api.controllers.security_controller.remove_nones_to_dict'):
                    with patch('api.controllers.security_controller.security_revoke_tokens', return_value=AsyncMock()):
                        calls = [call(f=security.update_security_config,
                                      f_kwargs=ANY,
                                      request_type='local_master',
                                      is_async=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request['token_info']['rbac_policies'],
                                      wait_for_complete=False
                                      )
                                 ]
                        result = await put_security_config(request=mock_request)
                        mock_dapi.assert_has_calls(calls)
                        mock_exc.assert_called_once_with(mock_dfunc.return_value)
                        assert isinstance(result, web_response.Response)

    async def test_delete_security_config():
        with patch('api.controllers.security_controller.SecurityConfigurationModel.get_kwargs',
                   return_value=AsyncMock()):
            with patch('api.controllers.security_controller.security_revoke_tokens', return_value=AsyncMock()):
                calls = [call(f=security.update_security_config,
                              f_kwargs=ANY,
                              request_type='local_master',
                              is_async=False,
                              logger=ANY,
                              wait_for_complete=False,
                              rbac_permissions=mock_request['token_info']['rbac_policies']
                              )
                         ]
                result = await delete_security_config(request=mock_request)
                mock_dapi.assert_has_calls(calls)
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                assert isinstance(result, web_response.Response)

    # Function list containing all sub tests declared above.
    functions = [test_login_user(),
                 test_login_user_raise(),
                 test_run_as_login(),
                 test_run_as_login_raise(),
                 test_get_user_me(),
                 test_get_user_me_policies(),
                 test_logout_user(),
                 test_get_users(),
                 test_edit_run_as(),
                 test_create_user(),
                 test_update_user(),
                 test_delete_users(),
                 test_get_roles(),
                 test_add_role(),
                 test_remove_roles(),
                 test_update_role(),
                 test_get_rules(),
                 test_add_rule(),
                 test_update_rule(),
                 test_remove_rules(),
                 test_get_policies(),
                 test_add_policy(),
                 test_remove_policies(),
                 test_update_policy(),
                 test_set_user_role(),
                 test_remove_user_role(),
                 test_set_role_policy(),
                 test_remove_role_policy(),
                 test_set_role_rule(),
                 test_remove_role_rule(),
                 test_get_rbac_resources(),
                 test_get_rbac_actions(),
                 test_revoke_all_tokens(),
                 test_get_security_config(),
                 test_security_revoke_tokens(),
                 test_put_security_config(),
                 test_delete_security_config()
                 ]
    for test_funct in functions:
        with patch('api.controllers.security_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.security_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.security_controller.raise_if_exc',
                           return_value=CustomMagicMockReturn()) as mock_exc:
                    with patch('api.controllers.security_controller.generate_token',
                               return_value='token') as mock_token:
                        await test_funct
