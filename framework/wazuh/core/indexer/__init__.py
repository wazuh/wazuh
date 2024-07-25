import os
import random
from asyncio import sleep
from logging import getLogger

from opensearchpy import AsyncOpenSearch
from wazuh.core.exception import WazuhIndexerError

logger = getLogger('wazuh')

HOST_KEY = 'host'
PORT_KEY = 'port'


class Indexer:
    """Interface to connect with Wazuh Indexer."""

    def __init__(
        self,
        host: str,
        user: str = '',
        password: str = '',
        port: int = 9200,
        use_ssl: bool = True,
        client_cert_path: str = '',
        client_key_path: str = '',
        verify_certs: bool = True,
        ca_certs_path: str = '',
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.client_cert = client_cert_path
        self.client_key = client_key_path
        self.verify_certs = verify_certs
        self.ca_certs = ca_certs_path

        self._client = self._get_opensearch_client()

        # Register index clients here

    def _get_opensearch_client(self) -> AsyncOpenSearch:
        """Get a new OpenSearch client instance.

        Raises
        ------
        WazuhIndexerError
            In case authentication is not provided.

        Returns
        -------
        AsyncOpenSearch
            The created instance.
        """
        parameters = {
            'hosts': [{HOST_KEY: self.host, PORT_KEY: self.port}],
            'http_compress': True,
            'use_ssl': self.use_ssl,
            'verify_certs': self.verify_certs,
            'ca_certs': self.ca_certs,
        }

        if all([self.user, self.password]):
            parameters.update({'http_auth': (self.user, self.password)})
        elif all([self.client_cert, self.client_key]):
            parameters.update({'client_cert': self.client_cert, 'client_key': self.client_key})
        else:
            raise WazuhIndexerError(
                2201,
                extra_message=(
                    'Some type of authentication must be provided, `user` and `password` for BASIC_HTTP_AUTH '
                    'or the client certificates `client_cert_path` and `client_key_path`.'
                )
            )

        return AsyncOpenSearch(**parameters)

    async def connect(self) -> None:
        """Connect to the Wazuh Indexer.

        Raises
        ------
        WazuhIndexerError
            In case of errors communicating with the Wazuh Indexer.
        """
        if not (await self._client.ping()):
            raise WazuhIndexerError(2200)

    async def close(self) -> None:
        """Close the Wazuh Indexer client."""
        logger.warning('Closing the indexer client session.')
        await self._client.close()


async def create_indexer(
    host: str,
    user: str = '',
    password: str = '',
    port: int = 9200,
    retries: int = 5,
    backoff_in_seconds: int = 1,
    **kwargs,
) -> Indexer:
    """Create and initialize the Indexer instance implementing a retry with backoff mechanism.

    Parameters
    ----------
    host : str
        Location of the Wazuh Indexer.
    user : str, optional
        User of the Wazuh Indexer to authenticate with.
    password : str, optional
        Password of the Wazuh Indexer to authenticate with.
    port : int, optional
        Port of the Wazuh Indexer to connect with, by default 9200
    retries : int, optional
        Number of retries, by default 5.
    backoff_in_seconds : int, optional
        Base seconds to wait, by default 1.

    Returns
    -------
    Indexer
        The new Indexer instance.
    """

    indexer = Indexer(host, user, password, port, **kwargs)
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
