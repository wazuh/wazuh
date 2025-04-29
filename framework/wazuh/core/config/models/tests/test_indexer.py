from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from wazuh.core.config.models.indexer import IndexerConfig
from wazuh.core.config.models.ssl_config import IndexerSSLConfig

with patch('os.path.isfile', return_value=True):
    with patch.object(IndexerSSLConfig, 'create_ca_bundle', return_value=None):
        SSL_CONFIG = IndexerSSLConfig(
            use_ssl=True, key='key_example', certificate='cert_example', certificate_authorities=['ca_example']
        )


@pytest.mark.parametrize(
    'init_values,expected',
    [
        (
            {
                'hosts': ['http://localhost:9200/'],
                'username': 'user_example',
                'password': 'password_example',
                'ssl': IndexerSSLConfig(),
            },
            {
                'hosts': ['http://localhost:9200/'],
                'username': 'user_example',
                'password': 'password_example',
                'ssl': IndexerSSLConfig(),
            },
        ),
        (
            {
                'hosts': ['https://example:5000/'],
                'username': 'another_user',
                'password': 'another_password',
                'ssl': SSL_CONFIG,
            },
            {
                'hosts': ['https://example:5000/'],
                'username': 'another_user',
                'password': 'another_password',
                'ssl': SSL_CONFIG,
            },
        ),
    ],
)
@patch('wazuh.core.config.models.indexer.KeystoreReader.__new__', return_value=None)
def test_indexer_config_default_values(keystore_mock, init_values, expected):
    """Check the correct initialization of the `IndexerConfig` class."""
    keystore_instance = MagicMock(
        **{'_keystore': {'indexer-username': expected['username'], 'indexer-password': expected['password']}}
    )
    keystore_instance.__getitem__ = lambda self, x: self._keystore[x]
    keystore_mock.return_value = keystore_instance

    config = IndexerConfig(**init_values)

    assert [str(host) for host in config.hosts] == [element for element in expected['hosts']]
    assert config.username == expected['username']
    assert config.password == expected['password']
    if config.ssl:
        assert config.ssl == expected['ssl']


@pytest.mark.parametrize(
    'init_values',
    [
        ({}),
        ({'hosts': []}),
        ({'hosts': [{'host': 'localhost'}]}),
        ({'hosts': [{'host': 'localhost', 'port': 5000}]}),
        ({'hosts': [{'host': 'localhost', 'port': 5000}], 'username': 'user_example'}),
    ],
)
def test_indexer_config_fails_without_values(init_values):
    """Check the correct behavior of the `IndexerConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = IndexerConfig(**init_values)
