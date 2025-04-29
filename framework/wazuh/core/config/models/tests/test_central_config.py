from unittest.mock import patch

import pytest
from wazuh.core.config.models.base import ValidateFilePathMixin
from wazuh.core.config.models.central_config import (
    CommsAPIConfig,
    Config,
    ConfigSections,
    EngineConfig,
    IndexerConfig,
    ManagementAPIConfig,
    ServerConfig,
)


def test_config_sections_ko():
    """Validate that the `ConfigSections` class instantiation with an invalid value raises an error."""
    value = 'test'
    with pytest.raises(ValueError, match=rf'.*{value}.*'):
        ConfigSections(value)


@pytest.mark.parametrize(
    'init_values, expected',
    [
        (
            {
                'indexer': {
                    'hosts': [{'host': 'localhost', 'port': 9200}],
                    'username': 'user_example',
                    'password': 'password_example',
                },
            },
            {
                'indexer': {
                    'hosts': [{'host': 'localhost', 'port': 9200}],
                    'username': 'user_example',
                    'password': 'password_example',
                },
                'server': {},
                'engine': {},
                'management_api': {},
                'communications_api': {},
            },
        ),
    ],
)
def test_config_default_values(init_values, expected):
    """Check the correct initialization of the `Config` class."""
    with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
        config = Config(**init_values)

        assert config.indexer == IndexerConfig(**expected['indexer'])
        assert config.engine == EngineConfig(**expected['engine'])
        assert config.server == ServerConfig(**expected['server'])
        assert config.management_api == ManagementAPIConfig(**expected['management_api'])
        assert config.communications_api == CommsAPIConfig(**expected['communications_api'])
