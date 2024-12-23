from unittest.mock import mock_open, patch

import pytest
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.central_config import (
    CommsAPIConfig,
    Config,
    ConfigSections,
    EngineConfig,
    IndexerConfig,
    ManagementAPIConfig,
)
from wazuh.core.config.models.server import DEFAULT_SERVER_INTERNAL_CONFIG, ServerConfig

mock_config_data = {
    'server': {
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['node1'],
        'node': {'name': 'example', 'type': 'master', 'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}},
        'worker': {},
        'master': {},
        'communications': {},
        'logging': {'level': 'debug2'},
        'cti': {},
    },
    'indexer': {
        'hosts': [{'host': 'localhost', 'port': 9200}],
        'username': 'admin',
        'password': 'password',
        'ssl': {'use_ssl': False, 'key': '', 'certificate': '', 'certificate_authorities': ['']},
    },
    'engine': {},
    'management_api': {},
    'communications_api': {},
}


@pytest.fixture
def patch_load():
    with patch.object(CentralizedConfig, 'load', return_value=None):
        CentralizedConfig._config = Config(**mock_config_data)
        yield
        CentralizedConfig._config = None


def test_get_comms_api_config(patch_load):
    """Check the correct behavior of the `get_comms_api_config` class method."""
    comms_api_config = CentralizedConfig.get_comms_api_config()
    assert comms_api_config == CommsAPIConfig(**mock_config_data['communications_api'])


def test_get_management_api_config(patch_load):
    """Check the correct behavior of the `get_management_api_config` class method."""
    management_api_config = CentralizedConfig.get_management_api_config()
    assert management_api_config == ManagementAPIConfig(**mock_config_data['management_api'])


def test_get_indexer_config(patch_load):
    """Check the correct behavior of the `get_indexer_config` class method."""
    indexer_config = CentralizedConfig.get_indexer_config()
    assert indexer_config == IndexerConfig(**mock_config_data['indexer'])


def test_get_engine_config(patch_load):
    """Check the correct behavior of the `get_engine_config` class method."""
    engine_config = CentralizedConfig.get_engine_config()
    assert engine_config == EngineConfig(**mock_config_data['engine'])


def test_get_server_config(patch_load):
    """Check the correct behavior of the `get_server_config` class method."""
    server_config = CentralizedConfig.get_server_config()
    assert server_config == ServerConfig(**mock_config_data['server'])


def test_get_server_internal_config(patch_load):
    """Check the correct behavior of the `get_internal_server_config` class method."""
    internal_config = CentralizedConfig.get_internal_server_config()
    assert internal_config == DEFAULT_SERVER_INTERNAL_CONFIG


@pytest.mark.parametrize(
    'updated_values, expected_yaml_update',
    [
        ({'auth_token_exp_timeout': 7200, 'rbac_mode': None}, {'auth_token_exp_timeout': 7200, 'rbac_mode': 'white'}),
        ({'auth_token_exp_timeout': None, 'rbac_mode': 'black'}, {'auth_token_exp_timeout': 900, 'rbac_mode': 'black'}),
        (
            {'auth_token_exp_timeout': 7200, 'rbac_mode': 'black'},
            {'auth_token_exp_timeout': 7200, 'rbac_mode': 'black'},
        ),
    ],
)
@patch('yaml.dump')
@patch('builtins.open', new_callable=mock_open)
def test_update_security_conf(mock_open_file, mock_yaml_dump, patch_load, updated_values, expected_yaml_update):
    """Check the correct behavior of the `get_internal_server_config` class method."""
    CentralizedConfig.update_security_conf(updated_values)

    assert (
        CentralizedConfig._config.management_api.jwt_expiration_timeout
        == expected_yaml_update['auth_token_exp_timeout']
    )
    assert CentralizedConfig._config.management_api.rbac_mode == expected_yaml_update['rbac_mode']
    mock_yaml_dump.assert_called_once()


def test_get_config_json(patch_load):
    """Check the correct behavior of the `test_get_config_json` class method."""
    engine_example = Config(**mock_config_data).model_dump_json(include=['engine'])
    obtained = CentralizedConfig.get_config_json(sections=[ConfigSections.ENGINE])

    assert obtained == engine_example


@patch('builtins.open', new_callable=mock_open)
@patch('yaml.dump')
@patch.object(CentralizedConfig, 'load')
@patch.object(CentralizedConfig, '_config', create=True)
def test_update_security_conf(mock_config, mock_load, mock_yaml_dump, mock_open):
    """Check the correct behavior of the `test_update_security_conf` class method."""
    mock_config.management_api.jwt_expiration_timeout = 3600
    mock_config.management_api.rbac_mode = 'disabled'
    mock_config.model_dump.return_value = {'auth_token_exp_timeout': 7200, 'rbac_mode': 'white'}

    new_config = {'auth_token_exp_timeout': 7200, 'rbac_mode': 'white'}

    CentralizedConfig.update_security_conf(new_config)

    assert mock_config.management_api.jwt_expiration_timeout == 7200
    assert mock_config.management_api.rbac_mode == 'white'
    mock_yaml_dump.assert_called_once_with(
        {'auth_token_exp_timeout': 7200, 'rbac_mode': 'white'}, mock_open().__enter__()
    )
