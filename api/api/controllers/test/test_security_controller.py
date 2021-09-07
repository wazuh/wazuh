import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
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
                                                         update_user,
                                                         WazuhException as wes)
        from wazuh import security
        from wazuh.core.exception import WazuhException
        from wazuh.rbac import preprocessor
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_user', ['user1'])
@pytest.mark.parametrize('mock_bool', [(True), (False)])
@pytest.mark.parametrize('mock_raise', [(True), (False)])
async def test_security_controller(mock_user, mock_bool, mock_raise):
    async def test_login_user():
        calls = [call(f=preprocessor.get_permissions,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      logger=ANY
                      )
                 ]
        if not mock_raise:
            result = await login_user(mock_user,
                                      raw=mock_bool)
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            assert isinstance(result, web_response.Response)
        # else:
        #     with pytest.raises(ValueError):
        #         mock_token.side_effect = ValueError
        #         result = await login_user(mock_user,
        #                                 raw=mock_bool)
        #         mock_dapi.assert_has_calls(calls)
        #         mock_exc.assert_called_once()
        #         assert isinstance(result, web_response.Response)

    async def test_run_as_login():
        pass

    async def test_get_user_me():
        pass

    async def test_get_user_me_policies():
        pass

    async def test_logout_user():
        pass

    async def test_get_users():
        pass

    async def test_edit_run_as():
        pass

    async def test_create_user():
        pass

    async def test_update_user():
        pass

    async def test_delete_users():
        pass

    async def test_get_roles():
        pass

    async def test_add_role():
        pass

    async def test_remove_roles():
        pass

    async def test_update_role():
        pass

    async def test_get_rules():
        pass

    async def test_add_rule():
        pass

    async def test_update_rule():
        pass

    async def test_remove_rules():
        pass

    async def test_get_policies():
        pass

    async def test_add_policy():
        pass

    async def test_remove_policies():
        pass

    async def test_update_policy():
        pass

    async def test_set_user_role():
        pass

    async def test_remove_user_role():
        pass

    async def test_set_role_policy():
        pass

    async def test_remove_role_policy():
        pass

    async def test_set_role_rule():
        pass

    async def test_remove_role_rule():
        pass

    async def test_get_rbac_resources():
        pass

    async def test_get_rbac_actions():
        pass

    async def test_revoke_all_tokens():
        pass

    async def test_get_security_config():
        pass

    async def test_security_revoke_tokens():
        pass

    async def test_put_security_config():
        pass

    async def test_delete_security_config():
        pass

    functions = [test_login_user(),
                 test_run_as_login(),
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
                with patch('api.controllers.security_controller.raise_if_exc') as mock_exc:
                    with patch('api.controllers.security_controller.generate_token',
                               return_value='token') as mock_token:
                        await test_funct
