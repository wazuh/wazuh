import pytest
from unittest.mock import patch
from wazuh.core.config.models.central_config import (
    CommsAPIConfig,
    Config,
    ConfigSections,
    EngineConfig,
    IndexerConfig,
    ManagementAPIConfig,
)
from wazuh.core.config.models.server import ValidateFilePathMixin


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
                'server': {
                    'nodes': ['master'],
                    'node': {
                        'name': 'example',
                        'type': 'master',
                        'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'},
                    },
                },
            },
            {
                'node': {'name': 'example', 'type': 'master', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}},
                'server': {
                    'nodes': ['master'],
                    'port': 1516,
                    'bind_addr': 'localhost',
                    'hidden': False,
                    'update_check': False,
                    'logging.level': 'info',
                },
                'indexer': {
                    'hosts': [{'host': 'localhost', 'port': 9200}],
                    'username': 'user_example',
                    'password': 'password_example',
                },
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

        assert config.server.port == expected['server']['port']
        assert config.server.bind_addr == expected['server']['bind_addr']
        assert config.server.hidden == expected['server']['hidden']
        assert config.server.update_check == expected['server']['update_check']
        assert config.server.logging.level == expected['server']['logging.level']

        assert config.indexer == IndexerConfig(**expected['indexer'])
        assert config.engine == EngineConfig(**expected['engine'])
        assert config.management_api == ManagementAPIConfig(**expected['management_api'])
        assert config.communications_api == CommsAPIConfig(**expected['communications_api'])
