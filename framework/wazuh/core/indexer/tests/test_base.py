from unittest import mock

from wazuh.core.indexer.base import BaseIndex


def test_base_index_init():
    """Check the correct initalization of the `BaseIndex` class."""

    client_mock = mock.MagicMock()
    instance = BaseIndex(client=client_mock)

    assert instance._client == client_mock
