import pytest
from pydantic import ValidationError

from wazuh.core.config.models.indexer import IndexerConfig
from wazuh.core.config.models.ssl_config import IndexerSSLConfig


@pytest.mark.parametrize("init_values,expected", [
    (
        {
            "host": "localhost",
            "port": 9200,
            "user": "user_example",
            "password": "password_example"
        },
        {
            "host": "localhost",
            "port": 9200,
            "user": "user_example",
            "password": "password_example",
            "ssl": IndexerSSLConfig()
        }
    ),
    (
        {
            "host": "example.com",
            "port": 9300,
            "user": "another_user",
            "password": "another_password",
            "ssl": IndexerSSLConfig(use_ssl=True, key="key_example", cert="cert_example")
        },
        {
            "host": "example.com",
            "port": 9300,
            "user": "another_user",
            "password": "another_password",
            "ssl": IndexerSSLConfig(use_ssl=True, key="key_example", cert="cert_example")
        }
    )
])
def test_indexer_config_default_values(init_values, expected):
    """Check the correct initialization of the `IndexerConfig` class."""
    config = IndexerConfig(**init_values)

    assert config.host == expected["host"]
    assert config.port == expected["port"]
    assert config.user == expected["user"]
    assert config.password == expected["password"]
    assert config.ssl == expected["ssl"]


@pytest.mark.parametrize("init_values", [
    ({}),
    ({"host": "localhost"}),
    ({"host": "localhost", "port": 9200}),
    ({"host": "localhost", "port": 9200, "user": "user_example"}),
])
def test_indexer_config_fails_without_values(init_values):
    """Check the correct behavior of the `IndexerConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = IndexerConfig(**init_values)
