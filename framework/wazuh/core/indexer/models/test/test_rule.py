import pytest
from wazuh.core.indexer.models.rule import Rule


class TestRule:
    """Validate the correct functionality of the `Rule` class."""

    @pytest.mark.parametrize(
        'data,expected',
        [
            (
                {
                    'id': '1',
                    'name': 'test',
                    'body': {},
                    'created_at': 0,
                },
                {
                    'id': '1',
                    'name': 'test',
                    'body': {},
                    'created_at': 0,
                },
            ),
            (
                {
                    'id': '1',
                    'name': 'test',
                    'created_at': None,
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
        rule = Rule(**data)
        assert rule.to_dict() == expected
