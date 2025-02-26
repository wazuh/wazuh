import pytest
from wazuh.core.indexer.models.policy import Effect, Policy


class TestPolicy:
    """Validate the correct functionality of the `Policy` class."""

    @pytest.mark.parametrize(
        'data,expected',
        [
            (
                {
                    'id': '1',
                    'name': 'test',
                    'level': 1,
                    'actions': ['agent:read'],
                    'resources': ['*:*:*'],
                    'effect': Effect.ALLOW,
                    'created_at': 0,
                },
                {
                    'id': '1',
                    'name': 'test',
                    'level': 1,
                    'actions': ['agent:read'],
                    'resources': ['*:*:*'],
                    'effect': Effect.ALLOW,
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
        policy = Policy(**data)
        assert policy.to_dict() == expected
