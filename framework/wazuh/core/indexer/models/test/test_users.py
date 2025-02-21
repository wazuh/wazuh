import pytest
from wazuh.core.indexer.models.users import User


class TestUser:
    """Validate the correct functionality of the `User` class."""

    @pytest.mark.parametrize(
        'data,expected',
        [
            (
                {
                    'id': '1',
                    'username': 'test',
                    'password': 'test',
                    'allow_run_as': False,
                    'roles': [{'id': '1'}],
                    'created_at': 0,
                },
                {
                    'id': '1',
                    'username': 'test',
                    'password': 'test',
                    'allow_run_as': False,
                    'roles': [{'id': '1'}],
                    'created_at': 0,
                },
            ),
            (
                {
                    'id': '1',
                    'username': 'test',
                    'password': None,
                },
                {
                    'id': '1',
                    'username': 'test',
                },
            ),
        ],
    )
    def test_to_dict(self, data: dict, expected):
        """Check the correct function if `to_dict` method."""
        user = User(**data)
        assert user.to_dict() == expected
