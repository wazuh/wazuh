import pytest
from unittest.mock import patch
from fastapi import status, HTTPException

from wazuh.core.config.client import CentralizedConfig
from wazuh.core.cluster.unix_server.config import get_config
from wazuh.core.config.models.central_config import Config


mock_config_data = {
    'server': {
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['node1'],
        'node': {
            'name': 'example',
            'type': 'master',
            'ssl': {'key': 'value', 'cert': 'value', 'ca': 'value'}
        },
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
        'ssl': {'use_ssl': False, 'key': "", 'certificate': "", 'certificate_authorities': [""]}
    },
    'engine': {},
    'management_api': {},
    'communications_api': {}
}


@pytest.fixture
def patch_load():
    with patch.object(CentralizedConfig, 'load', return_value=None):
        CentralizedConfig._config = Config(**mock_config_data)
        yield
        CentralizedConfig._config = None


async def test_get_config_all_sections(patch_load):
    """Verify that the `get_config` function works as expected with no sections specified."""
    expected = CentralizedConfig._config.model_dump_json()
    got = await get_config()

    assert got.status_code == status.HTTP_200_OK
    assert expected == got.body.decode('utf-8')


@pytest.mark.parametrize('sections', [
    (['engine']),
    (['engine', 'indexer']),
    (['communications_api']),
    (['management_api']),
    (['server', 'engine']),
    (['engine', 'indexer', 'server', 'communications_api', 'management_api'])
])
async def test_get_config_valid_sections(patch_load, sections):
    """Verify that the `get_config` function works as expected with sections specified."""
    expected = CentralizedConfig._config.model_dump_json(include=sections)
    got = await get_config(','.join(sections))

    assert got.status_code == status.HTTP_200_OK
    assert expected == got.body.decode('utf-8')


@pytest.mark.parametrize('sections', [
    'example',
    'engine,err'
])
async def test_get_config_invalid_sections(patch_load, sections):
    """Verify that the `get_config` function works as expected with invalid sections."""
    with pytest.raises(HTTPException) as exc:
        _ = await get_config(sections)

    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST
