import pytest
from pydantic import ValidationError

from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode
from wazuh.core.config.models.ssl_config import IndexerSSLConfig


@pytest.mark.parametrize("init_values,expected", [
    (
        {
            "hosts": [{"host": "localhost", "port": 9200}],
            "username": "user_example",
            "password": "password_example"
        },
        {
            "hosts": [{"host": "localhost", "port": 9200}],
            "username": "user_example",
            "password": "password_example",
            "ssl": IndexerSSLConfig()
        }
    ),
    (
        {
            "hosts": [{"host": "example", "port": 5000}],
            "username": "another_user",
            "password": "another_password",
            "ssl": IndexerSSLConfig(use_ssl=True, key="key_example", certificate="cert_example")
        },
        {
            "hosts": [{"host": "example", "port": 5000}],
            "username": "another_user",
            "password": "another_password",
            "ssl": IndexerSSLConfig(use_ssl=True, key="key_example", certificate="cert_example")
        }
    )
])
def test_indexer_config_default_values(init_values, expected):
    """Check the correct initialization of the `IndexerConfig` class."""
    config = IndexerConfig(**init_values)

    assert config.model_dump()["hosts"] == expected["hosts"]
    assert config.username == expected["username"]
    assert config.password == expected["password"]
    assert config.ssl == expected["ssl"]


@pytest.mark.parametrize("init_values", [
    ({}),
    ({"hosts": []}),
    ({"hosts": [{"host": "localhost"}]}),
    ({"hosts": [{"host": "localhost", "port": 5000}]}),
    ({"hosts": [{"host": "localhost", "port": 5000}], "username": "user_example"}),
])
def test_indexer_config_fails_without_values(init_values):
    """Check the correct behavior of the `IndexerConfig` class validations."""
    with pytest.raises(ValidationError):
        _ = IndexerConfig(**init_values)
