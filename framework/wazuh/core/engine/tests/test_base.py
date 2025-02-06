from unittest import mock

from wazuh.core.engine.base import BaseModule, convert_enums
from wazuh.core.engine.models.vulnerability import Type


def test_base_module_init():
    """Check the correct initialization of the `BaseModule` class."""
    client_mock = mock.MagicMock()
    instance = BaseModule(client=client_mock)

    assert instance._client == client_mock


def test_convert_enums():
    """Check the correct behavior of the `convert_enums` function."""
    d = {'key': None, 'key2': Type.PACKAGE_LIST}
    expected = {'key2': Type.PACKAGE_LIST.value}
    result = convert_enums(d.items())

    assert result == expected
