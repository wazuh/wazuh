import random
import ssl
from asyncio import sleep
from contextlib import asynccontextmanager
from logging import getLogger
from typing import AsyncIterator, List

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import ImproperlyConfigured, TransportError
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.ssl_config import IndexerSSLConfig
from wazuh.core.exception import WazuhIndexerError
from wazuh.core.indexer.agent import AgentsIndex
from wazuh.core.indexer.bulk import MixinBulk
from wazuh.core.indexer.commands import CommandsManager

logger = getLogger('wazuh')

HOST_KEY = 'host'
PORT_KEY = 'port'


class Indexer(MixinBulk):
    """Interface to connect with Wazuh Indexer."""

    def __init__(
        self,
        hosts: List[str],
        ports: List[int],
        user: str = '',
        password: str = '',
        use_ssl: bool = True,
        client_cert_path: str = '',
        client_key_path: str = '',
        verify_certs: bool = True,
        ca_certs_path: str = '',
    ) -> None:
        self.hosts = hosts
        self.user = user
        self.password = password
        self.ports = ports
        self.use_ssl = use_ssl
        self.client_cert = client_cert_path
        self.client_key = client_key_path
        self.verify_certs = verify_certs
        self.ca_certs = ca_certs_path

        self._client = self._get_opensearch_client()

        # Register indices and plugins clients here
        self.agents = AgentsIndex(client=self._client)
        self.commands_manager = CommandsManager(client=self._client)

    def _get_opensearch_client(self) -> AsyncOpenSearch:
        """Get a new OpenSearch client instance.

        Raises
        ------
        WazuhIndexerError
            In case authentication is not provided.

        Raises
        ------
        WazuhIndexerError(2201)
            In case of no authentication credentials were specified.

        Returns
        -------
        AsyncOpenSearch
            The created instance.
        """
        parameters = {
            'hosts': [{HOST_KEY: host, PORT_KEY: port} for (host, port) in zip(self.hosts, self.ports)],
            'http_compress': True,
            'use_ssl': self.use_ssl,
            'verify_certs': self.verify_certs,
            'ca_certs': self.ca_certs,
        }

        if all([self.user, self.password]):
            parameters.update({'http_auth': (self.user, self.password)})
        else:
            raise WazuhIndexerError(2201, extra_message="'user' and 'password' are required")

        if self.use_ssl:
            if all([self.client_cert, self.client_key]):
                parameters.update({'client_cert': self.client_cert, 'client_key': self.client_key})
            else:
                raise WazuhIndexerError(2201, extra_message='SSL certificates paths missing in the configuration')

        return AsyncOpenSearch(**parameters)

    async def connect(self) -> None:
        """Connect to the Wazuh Indexer.

        Raises
        ------
        WazuhIndexerError(2200)
            In case of errors communicating with the Wazuh Indexer.
        """
        logger.debug('Connecting to the indexer client.')
        try:
            return await self._client.info()
        except (ConnectionError, TransportError) as e:
            raise WazuhIndexerError(2200, extra_message=e.error)
        except ssl.SSLError as e:
            raise WazuhIndexerError(2200, extra_message=e.reason)
        except ImproperlyConfigured as e:
            raise WazuhIndexerError(2200, extra_message=f'{e}. Check your indexer configuration and SSL certificates')

    async def close(self) -> None:
        """Close the Wazuh Indexer client."""
        logger.debug('Closing the indexer client session.')
        await self._client.close()


async def create_indexer(
    hosts: List[str],
    ports: List[int],
    user: str = '',
    password: str = '',
    ssl: IndexerSSLConfig = None,
    retries: int = 5,
    backoff_in_seconds: int = 1,
) -> Indexer:
    """Create and initialize the Indexer instance implementing a retry with backoff mechanism.

    Parameters
    ----------
    hosts : List[str]
        Wazuh indexer nodes hosts.
    ports : List[int]
        Wazuh indexer nodes ports.
    user : str, optional
        User of the Wazuh Indexer to authenticate with.
    password : str, optional
        Password of the Wazuh Indexer to authenticate with.
    ssl : IndexerSSLConfig
        SSL configuration parameters.
    retries : int, optional
        Number of retries, by default 5.
    backoff_in_seconds : int, optional
        Base seconds to wait, by default 1.

    Returns
    -------
    Indexer
        The new Indexer instance.
    """
    if ssl is None:
        ssl = IndexerSSLConfig(use_ssl=False)

    indexer = Indexer(
        hosts=hosts,
        ports=ports,
        user=user,
        password=password,
        use_ssl=ssl.use_ssl,
        client_cert_path=ssl.certificate,
        client_key_path=ssl.key,
        ca_certs_path=ssl.certificate_authorities[0],
        verify_certs=ssl.verify_certificates,
    )

    retries_count = 0
    while True:
        try:
            await indexer.connect()
            return indexer
        except WazuhIndexerError:
            if retries_count == retries:
                await indexer.close()
                raise

            wait = backoff_in_seconds * 2**retries_count + random.uniform(0, 1)
            logger.warning('Cannot initialize the indexer client.')
            logger.info(f'Sleeping {wait}s until next try.')
            await sleep(wait)
            retries_count += 1


@asynccontextmanager
async def get_indexer_client() -> AsyncIterator[Indexer]:
    """Create and return the indexer client."""
    indexer_config = CentralizedConfig.get_indexer_config()
    list_of_hosts = []
    list_of_ports = []
    for instance in indexer_config.hosts:
        list_of_hosts.append(instance.host)
        list_of_ports.append(instance.port)

    client = await create_indexer(
        hosts=list_of_hosts,
        ports=list_of_ports,
        user=indexer_config.username,
        password=indexer_config.password,
        ssl=indexer_config.ssl if indexer_config.ssl else None,
        retries=3,
    )

    try:
        yield client
    finally:
        await client.close()
