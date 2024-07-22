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
        user: str,
        password: str,
        port: int = 9200,
        use_ssl: bool = True,
        verify_certs: bool = True,
        ca_certs: str = ''
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs
        self.ca_certs = ca_certs

        self._client = self._get_opensearch_client()

        # Register index clients here

    def _get_opensearch_client(self) -> AsyncOpenSearch:
        """Get the a new instance of the opensearch client.

        Returns
        -------
        AsyncOpenSearch
            The created instance.
        """
        return AsyncOpenSearch(
            hosts=[{HOST_KEY: self.host, PORT_KEY: self.port}],
            http_compress=True,
            http_auth=(self.user, self.password),
            use_ssl=self.use_ssl,
            verify_certs=self.verify_certs,
            ca_certs=self.ca_certs
        )

    async def initiazlize(self):
        """Initialize the Wazuh Indexer connection.

        Raises
        ------
        WazuhIndexerError
            In case of errors communicating with the Wazuh Indexer.
        """
        if not (await self._client.ping()):
            raise WazuhIndexerError(2200)

    async def close(self):
        """Close the Wazuh Indexer client."""
        await self._client.close()


async def create_indexer(
    host: str,
    user: str,
    password: str,
    port: int = 9200,
    retries: int = 5,
    backoff_in_seconds: int = 1,
    **kwargs,
) -> Indexer:
    """Create and initialize the Indexer instance implementing a retry with backoff machanism.

    Parameters
    ----------
    host : str, optional
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
            await indexer.initiazlize()
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
