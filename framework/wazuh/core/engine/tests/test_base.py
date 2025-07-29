from unittest import mock

from wazuh.core.engine.base import BaseModule


def test_base_module_init():
    """Check the correct initialization of the `BaseModule` class."""

    client_mock = mock.MagicMock()
    instance = BaseModule(client=client_mock)

    assert instance._client == client_mock
