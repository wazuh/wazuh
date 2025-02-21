import pytest
from wazuh.core.indexer.models.roles import Role


class TestRole:
    """Validate the correct functionality of the `Role` class."""

    @pytest.mark.parametrize(
        'data,expected',
        [
            (
                {
                    'id': '1',
                    'name': 'test',
                    'level': 1,
                    'policies': [{'id': '1'}],
                    'rules': [{'id': '1'}],
                    'created_at': 0,
                },
                {
                    'id': '1',
                    'name': 'test',
                    'level': 1,
                    'policies': [{'id': '1'}],
                    'rules': [{'id': '1'}],
                    'created_at': 0,
                },
            ),
            (
                {
                    'id': '1',
                    'name': 'test',
                    'level': None,
                },
                {
                    'id': '1',
                    'name': 'test',
                },
            ),
        ],
    )
    def test_to_dict(self, data: dict, expected):
        """Check the correct function if `to_dict` method."""
        role = Role(**data)
        assert role.to_dict() == expected
