from dataclasses import asdict
from unittest import mock

from wazuh.core.indexer.base import BaseIndex, remove_empty_values
from wazuh.core.indexer.models.agent import Agent


def test_base_index_init():
    """Check the correct initalization of the `BaseIndex` class."""
    client_mock = mock.MagicMock()
    instance = BaseIndex(client=client_mock)

    assert instance._client == client_mock


def test_remove_empty_values():
    """Check the correct behavior of the `remove_empty_values` function."""
    d = {'key': None, 'key2': 1}
    expected = {'key2': 1}
    result = remove_empty_values(d.items())

    assert result == expected


def test_remove_empty_values_asdict():
    """Check the correct behavior of the `remove_empty_values` function as a dictionary factory."""
    agent = Agent(id='test', name='wazuh')
    expected = {'id': 'test', 'name': 'wazuh'}
    result = asdict(agent, dict_factory=remove_empty_values)

    assert result == expected
