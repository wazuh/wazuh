from unittest.mock import patch

from wazuh.core.indexer.models.rbac import Policy, Role, Rule, User
from wazuh.core.rbac import get_policies, get_roles, get_rules, get_users


@patch('wazuh.core.indexer.create_indexer')
async def test_get_policies(create_indexer_mock):
    """Validate that `get_policies` returns all policies stored in the indexer."""
    expected_policies = [
        Policy(id='1'),
        Policy(id='2'),
        Policy(id='3'),
    ]

    create_indexer_mock.return_value.policies.search.return_value = expected_policies
    policies = await get_policies()

    assert expected_policies == policies


@patch('wazuh.core.indexer.create_indexer')
async def test_get_roles(create_indexer_mock):
    """Validate that `get_roles` returns all roles stored in the indexer."""
    expected_roles = [
        Role(id='1'),
        Role(id='2'),
        Role(id='3'),
    ]

    create_indexer_mock.return_value.roles.search.return_value = expected_roles
    roles = await get_roles()

    assert expected_roles == roles


@patch('wazuh.core.indexer.create_indexer')
async def test_get_rules(create_indexer_mock):
    """Validate that `get_rules` returns all rules stored in the indexer."""
    expected_rules = [
        Rule(id='1'),
        Rule(id='2'),
        Rule(id='3'),
    ]

    create_indexer_mock.return_value.rules.search.return_value = expected_rules
    rules = await get_rules()

    assert expected_rules == rules


@patch('wazuh.core.indexer.create_indexer')
async def test_get_users(create_indexer_mock):
    """Validate that `get_users` returns all users stored in the indexer."""
    expected_users = [
        User(id='1'),
        User(id='2'),
        User(id='3'),
    ]

    create_indexer_mock.return_value.users.search.return_value = expected_users
    users = await get_users()

    assert expected_users == users
