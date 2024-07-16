import os

from core.exception import WazuhIndexerError
from opensearchpy import AsyncOpenSearch

HOST_KEY = 'host'
PORT_KEY = 'port'

# This constants are temporary
INDEXER_HOST = os.environ.get('WAZUH_INDEXER_HOST' 'wazuh-indexer')
INDEXER_PORT = os.environ.get('WAZUH_INDEXER_PORT', 9200)
INDEXER_USER = os.environ.get('WAZUH_INDEXER_USER', 'admin')
INDEXER_PASSWORD = os.environ.get('WAZUH_INDEXER_PASSWORD', 'SecretPassword1%')


class Indexer:
    """Interface to connect with Wazuh Indexer."""

    def __init__(
        self,
        host: str = INDEXER_HOST,
        user: str = INDEXER_USER,
        password: str = INDEXER_PASSWORD,
        port: int = INDEXER_PORT,
        use_ssl: bool = True,
        verify_certs: bool = True,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs

        self._client = self._get_opensearch_client()

        # Register index clients here

    def _get_opensearch_client(self) -> AsyncOpenSearch:
        """Get the a new instance of the opensearch client.

        Returns
        -------
        AsyncOpenSearch
            The created instance.
        """
        self._client = AsyncOpenSearch(
            hosts=[{HOST_KEY: self.host, PORT_KEY: self.port}],
            http_compress=True,
            http_auth=(self.user, self.password),
            use_ssl=self.use_ssl,
            verify_certs=self.verify_certs,
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


async def create_indexer(
    host: str = INDEXER_HOST,
    user: str = INDEXER_USER,
    password: str = INDEXER_PASSWORD,
    port: int = INDEXER_PORT,
    **kwargs,
) -> Indexer:
    """Create and initialize the Indexer.

    Parameters
    ----------
    host : str, optional
        Location of the Wazuh Indexer, by default INDEXER_HOST
    user : str, optional
        User of the Wazuh Indexer to authenticate with, by default INDEXER_USER
    password : str, optional
        Password of the Wazuh Indexer to authenticate with, by default INDEXER_PASSWORD
    port : int, optional
        Port of the Wazuh Indexer to connect with, by default INDEXER_PORT

    Returns
    -------
    Indexer
        The new Indexer instance.
    """

    indexer = Indexer(host, user, password, port, **kwargs)
    await indexer.initiazlize()

    return indexer
