from unittest import mock

import pytest
from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import TransportError

from wazuh.core.exception import WazuhIndexerError
from wazuh.core.indexer import Indexer, create_indexer, get_indexer_client
from wazuh.core.config.models.indexer import IndexerConfig, IndexerNode


@pytest.fixture
def indexer_instance_with_mocked_client() -> Indexer:
    indexer_instance = Indexer(hosts=['test'], ports=[9200], user='user_test', password='password_test', use_ssl=False)
    indexer_instance._client = mock.AsyncMock()
    return indexer_instance


class TestIndexer:
    @pytest.mark.parametrize(
        'params',
        [
            {'user': 'user_test', 'password': 'password_test', 'use_ssl': False},
            {'user': 'user_test', 'password': 'password_test', 'client_cert_path': '/tmp/client.pem', 
             'client_key_path': '/tmp/client-key.pem'},
        ],
    )
    def test_indexer_init(self, params: dict):
        """Check the correct initalization of the `Indexer` class."""
        indexer_instance = Indexer(hosts=['test'], ports=[9200], **params)

        assert isinstance(indexer_instance._client, AsyncOpenSearch)

    @pytest.mark.parametrize(
        'params',
        [
            {'user': 'user_test'},
            {'password': 'password_test'},
            {'client_cert_path': '/tmp/client.pem'},
            {'client_key_path': '/tmp/client-key.pem'},
            {},
        ],
    )
    def test_indexer_init_ko(self, params: dict):
        """Check the correct initalization of the `Indexer` class."""
        with pytest.raises(WazuhIndexerError, match='.*2201.*'):
            Indexer(hosts=['test'], ports=[9200], **params)

    async def test_connect(self, indexer_instance_with_mocked_client):
        """Check the correct function of `connect` method."""

        indexer_instance_with_mocked_client._client.info.return_value = True
        await indexer_instance_with_mocked_client.connect()

        indexer_instance_with_mocked_client._client.info.assert_called_once()

    async def test_connect_ko(self, indexer_instance_with_mocked_client):
        """Check the correct raise of `connect` method."""

        indexer_instance_with_mocked_client._client.info.side_effect = TransportError('', '')

        with pytest.raises(WazuhIndexerError, match='.*2200.*'):
            await indexer_instance_with_mocked_client.connect()

    async def test_close(self, indexer_instance_with_mocked_client):
        """Check the correct function of `close` method."""

        await indexer_instance_with_mocked_client.close()

        indexer_instance_with_mocked_client._client.close.assert_called_once()


@mock.patch('wazuh.core.indexer.Indexer', autospec=True)
async def test_create_indexer(indexer_mock: mock.AsyncMock):
    """Check the correct function of `create_index`."""

    hosts = ['test']
    ports = [9200]
    user = 'user_test'
    password = 'password_test'

    instance_mock = await create_indexer(hosts=hosts, ports=ports, user=user, password=password)
    indexer_mock.assert_called_once_with(
        hosts=hosts,
        ports=ports,
        user=user,
        password=password,
        use_ssl=False,
        client_cert_path='',
        client_key_path='',
        ca_certs_path='',
        verify_certs=True,
    )
    instance_mock.connect.assert_called_once()


@pytest.mark.parametrize('retries', [2, 4])
@mock.patch('wazuh.core.indexer.Indexer', autospec=True)
async def test_create_indexer_ko(indexer_mock: mock.AsyncMock, retries: int):
    """Check the correct raise of `create_index`."""

    hosts = ['test']
    ports = [9200]
    user = 'user_test'
    password = 'password_test'

    instance_mock = mock.AsyncMock()
    instance_mock.connect.side_effect = WazuhIndexerError(2200)
    indexer_mock.return_value = instance_mock

    with mock.patch('wazuh.core.indexer.sleep') as sleep_mock:
        with pytest.raises(WazuhIndexerError, match='.*2200.*'):
            instance_mock = await create_indexer(
                hosts=hosts,
                ports=ports,
                user=user,
                password=password,
                retries=retries)

        assert instance_mock.connect.call_count == retries + 1
        instance_mock.close.assert_called_once()
        assert sleep_mock.call_count == retries


@mock.patch('wazuh.core.indexer.create_indexer')
@mock.patch('wazuh.core.config.client.CentralizedConfig.get_indexer_config')
async def test_get_indexer_client( get_indexer_config_mock, create_indexer_mock):
    """Check the correct function of `get_indexer_client`."""
    config_test = IndexerConfig(
        hosts=[IndexerNode(host='example', port=9200)],
        username='user',
        password='password',
    )
    get_indexer_config_mock.return_value = config_test

    client_mock = mock.AsyncMock()
    create_indexer_mock.return_value = client_mock
    async with get_indexer_client() as indexer:
        create_indexer_mock.assert_called_once_with(
            hosts=['example'],
            ports=[9200],
            user='user',
            password='password',
            ssl=None,
            retries=1,
        )
        assert indexer == client_mock
    client_mock.close.assert_called_once()
