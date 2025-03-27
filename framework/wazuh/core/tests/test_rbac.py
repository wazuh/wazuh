from unittest.mock import AsyncMock, call, patch

import pytest
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.indexer.models.rbac import Policy, Role, Rule, User
from wazuh.core.rbac import RBACManager

USER_ID = '01915801-4b34-7131-9d88-ff06ff05aefd'


@pytest.fixture
@patch('wazuh.core.rbac.SyncManager')
def rbac_manager_mock(sync_manager_mock) -> RBACManager:
    """Create the RBAC manager mock initializing its dictionaries to facilitate testing."""
    rbac_manager = RBACManager()
    rbac_manager._users = {}
    rbac_manager._roles = {}
    rbac_manager._policies = {}
    rbac_manager._rules = {}

    return rbac_manager


@patch('wazuh.core.rbac.SyncManager')
def test_rbac_manager_initialization(sync_manager_mock):
    """Check that the `RBACManager.__init___` method works as expected."""
    RBACManager()

    sync_manager_mock.assert_has_calls(
        [
            call(),
            call().start(),
            call().dict(),
            call().dict(),
            call().dict(),
            call().dict(),
        ]
    )


@patch('wazuh.core.indexer.CentralizedConfig')
@patch('wazuh.core.indexer.create_indexer')
async def test_rbac_manager_update(create_indexer_mock, config_mock, rbac_manager_mock: RBACManager):
    """Check that the `update` method works as expected."""
    search_mock = AsyncMock(
        return_value=[
            User(
                id=USER_ID,
                roles=[
                    Role(
                        name='0',
                        policies=[
                            Policy(name='0'),
                            Policy(name='1'),
                        ],
                        rules=[
                            Rule(name='0'),
                            Rule(name='1'),
                            Rule(name='2'),
                        ],
                    ),
                    Role(
                        name='1',
                        policies=[
                            Policy(name='0'),
                            Policy(name='2'),
                        ],
                        rules=[
                            Rule(name='0'),
                            Rule(name='1'),
                            Rule(name='2'),
                        ],
                    ),
                ],
            )
        ]
    )
    create_indexer_mock.return_value.users.search = search_mock

    await rbac_manager_mock.update()

    assert rbac_manager_mock._users == {user.id: user for user in search_mock.return_value}
    assert rbac_manager_mock._roles == {
        '0': search_mock.return_value[0].roles[0],
        '1': search_mock.return_value[0].roles[1],
    }
    assert rbac_manager_mock._policies == {
        '0': search_mock.return_value[0].roles[0].policies[0],
        '1': search_mock.return_value[0].roles[0].policies[1],
        '2': search_mock.return_value[0].roles[1].policies[1],
    }
    assert rbac_manager_mock._rules == {
        '0': search_mock.return_value[0].roles[0].rules[0],
        '1': search_mock.return_value[0].roles[0].rules[1],
        '2': search_mock.return_value[0].roles[0].rules[2],
    }


async def test_rbac_manager_get_user(rbac_manager_mock: RBACManager):
    """Check that the `get_user` method works as expected."""
    rbac_manager_mock._users = {USER_ID: User()}
    user = rbac_manager_mock.get_user(USER_ID)

    assert user == rbac_manager_mock._users.get(USER_ID)


async def test_rbac_manager_get_user_ko(rbac_manager_mock: RBACManager):
    """Check that the `get_user` handles exceptions successfully."""
    rbac_manager_mock._users = {}
    with pytest.raises(WazuhResourceNotFound, match=r'4027'):
        rbac_manager_mock.get_user(USER_ID)


async def test_rbac_manager_get_users(rbac_manager_mock: RBACManager):
    """Check that the `get_users` method works as expected."""
    expected_users = [User(id='0'), User(id='1'), User(id='2')]
    rbac_manager_mock._users = {'0': User(id='0'), '1': User(id='1'), '2': User(id='2')}
    users = rbac_manager_mock.get_users()

    assert users == expected_users


async def test_rbac_manager_get_role(rbac_manager_mock: RBACManager):
    """Check that the `get_role` method works as expected."""
    role_name = 'test_role'
    expected_role = Role(name=role_name)

    rbac_manager_mock._roles = {role_name: expected_role}
    role = rbac_manager_mock.get_role(role_name)

    assert role == expected_role


async def test_rbac_manager_get_role_ko(rbac_manager_mock: RBACManager):
    """Check that the `get_role` handles exceptions successfully."""
    role_name = '0'

    rbac_manager_mock._roles = {
        '1': Role(name='1'),
        '2': Role(name='2'),
    }
    with pytest.raises(WazuhResourceNotFound, match=r'4027'):
        rbac_manager_mock.get_role(role_name)


async def test_rbac_manager_get_roles(rbac_manager_mock: RBACManager):
    """Check that the `get_roles` method works as expected."""
    expected_roles = [Role(name='0'), Role(name='1'), Role(name='2')]
    rbac_manager_mock._roles = {
        '0': Role(name='0'),
        '1': Role(name='1'),
        '2': Role(name='2'),
    }
    roles = rbac_manager_mock.get_roles()

    assert roles == expected_roles


async def test_rbac_manager_get_policy(rbac_manager_mock: RBACManager):
    """Check that the `get_policy` method works as expected."""
    policy_name = 'test_policy'
    expected_policy = Policy(name=policy_name)

    rbac_manager_mock._policies = {policy_name: expected_policy}
    policy = rbac_manager_mock.get_policy(policy_name)

    assert policy == expected_policy


async def test_rbac_manager_get_policy_ko(rbac_manager_mock: RBACManager):
    """Check that the `get_policy` handles exceptions successfully."""
    policy_name = '0'

    rbac_manager_mock._users = {
        '1': Policy(name='1'),
        '2': Policy(name='2'),
    }
    with pytest.raises(WazuhResourceNotFound, match=r'4027'):
        rbac_manager_mock.get_policy(policy_name)


async def test_rbac_manager_get_policies(rbac_manager_mock: RBACManager):
    """Check that the `get_policies` method works as expected."""
    expected_policies = [Policy(name='0'), Policy(name='1'), Policy(name='2')]
    rbac_manager_mock._policies = {
        '0': Policy(name='0'),
        '1': Policy(name='1'),
        '2': Policy(name='2'),
    }
    policies = rbac_manager_mock.get_policies()

    assert policies == expected_policies


async def test_rbac_manager_get_rule(rbac_manager_mock: RBACManager):
    """Check that the `get_rule` method works as expected."""
    rule_name = 'test_rule'
    expected_rule = Rule(name=rule_name)

    rbac_manager_mock._rules = {rule_name: expected_rule}
    rule = rbac_manager_mock.get_rule(rule_name)

    assert rule == expected_rule


async def test_rbac_manager_get_rule_ko(rbac_manager_mock: RBACManager):
    """Check that the `get_rule` handles exceptions successfully."""
    rule_name = '0'

    rbac_manager_mock._rules = {
        '1': Rule(name='1'),
        '2': Rule(name='2'),
    }
    with pytest.raises(WazuhResourceNotFound, match=r'4027'):
        rbac_manager_mock.get_rule(rule_name)


async def test_rbac_manager_get_rules(rbac_manager_mock: RBACManager):
    """Check that the `get_rules` method works as expected."""
    expected_rules = [Rule(name='0'), Rule(name='1'), Rule(name='2')]
    rbac_manager_mock._rules = {
        '0': Rule(name='0'),
        '1': Rule(name='1'),
        '2': Rule(name='2'),
    }
    rules = rbac_manager_mock.get_rules()

    assert rules == expected_rules
