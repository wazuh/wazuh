from unittest.mock import patch

from wazuh.core.indexer.models.rbac import User
from wazuh.core.rbac import get_users


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
