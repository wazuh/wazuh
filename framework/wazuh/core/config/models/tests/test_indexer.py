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
@patch('wazuh.core.config.models.indexer.KeystoreReader', return_value=None)
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
        ({'hosts': ['localhost']}),
        ({'hosts': ['localhost:5000']}),
    ],
)
def test_indexer_config_fails_without_values(init_values):
    """Check the correct behavior of the `IndexerConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = IndexerConfig(**init_values)


@pytest.mark.parametrize('keystore_value', [{'foo': 'bar'}, {'indexer-username': 'test'}, {'indexer-password': 'test'}])
@patch('wazuh.core.config.models.indexer.KeystoreReader', return_value=None)
def test_indexer_config_fails_if_key_is_not_in_keystore(keystore_mock, keystore_value):
    """Check for validation error when expected key is not in the keystore."""
    keystore_instance = MagicMock(**{'_keystore': keystore_value})
    keystore_instance.__getitem__ = lambda self, x: self._keystore[x]
    keystore_mock.return_value = keystore_instance

    with pytest.raises(ValidationError):
        IndexerConfig(
            **{
                'hosts': ['https://example:5000/'],
                'ssl': SSL_CONFIG,
            }
        )


@pytest.mark.parametrize(
    'hosts, use_ssl',
    [
        (['http://localhost:9200'], True),
        (['http://localhost:9200', 'https://localhost:9201'], True),
        (['https://localhost:9200'], False),
        (['http://localhost:9200', 'https://localhost:9201'], False),
    ],
)
@patch('wazuh.core.config.models.indexer.KeystoreReader', return_value=None)
def test_indexer_config_validate_url_scheme(keystore_mock, hosts, use_ssl):
    """Check `IndexerConfig` hosts scheme depending of ssl.use_ssl."""
    keystore_instance = MagicMock(**{'_keystore': {'indexer-username': 'admin', 'indexer-password': 'admin'}})
    keystore_instance.__getitem__ = lambda self, x: self._keystore[x]
    keystore_mock.return_value = keystore_instance

    ssl_config = SSL_CONFIG.model_copy()
    ssl_config.use_ssl = use_ssl

    with pytest.raises(ValidationError):
        IndexerConfig(hosts=hosts, ssl=ssl_config)
