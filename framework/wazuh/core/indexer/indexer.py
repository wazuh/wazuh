import random
import ssl
from asyncio import sleep
from contextlib import asynccontextmanager
from logging import getLogger
from typing import AsyncIterator, List
from urllib.parse import urlparse

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import ImproperlyConfigured, TransportError
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.exception import WazuhIndexerError
from wazuh.core.indexer.credential_manager import KeystoreClient
from wazuh.core.indexer.max_version_components import MaxVersionIndex


class Indexer():
    """
    Interface to connect with Wazuh Indexer.

    This class handles the asynchronous connection to the Wazuh Indexer
    (OpenSearch) nodes, managing authentication and SSL configuration.

    Parameters
    ----------
    hosts : List[str]
        List of hostnames or IP addresses of the Wazuh Indexer nodes.
    ports : List[int]
        List of ports corresponding to the hosts.
    user : str, optional
        Username for authentication. Defaults to an empty string.
    password : str, optional
        Password for authentication. Defaults to an empty string.
    use_ssl : bool, optional
        Whether to use SSL for the connection. Defaults to True.
    client_cert_path : str, optional
        Path to the client SSL certificate. Defaults to an empty string.
    client_key_path : str, optional
        Path to the client SSL key. Defaults to an empty string.
    verify_certs : bool, optional
        Whether to verify SSL certificates. Defaults to True.
    ca_certs_path : str, optional
        Path to CA certificates. Defaults to an empty string.

    Attributes
    ----------
    hosts : List[str]
        The list of configured hosts.
    ports : List[int]
        The list of configured ports.
    max_version_components : MaxVersionIndex
        Component to manage index versioning.

    Raises
    ------
    WazuhIndexerError
        If the number of hosts does not match the number of ports.
    """

    def __init__(
        self,
        hosts: List[str],
        ports: List[int],
        user: str = "",
        password: str = "",
        use_ssl: bool = True,
        client_cert_path: str = "",
        client_key_path: str = "",
        verify_certs: bool = True,
        ca_certs_path: str = "",
    ) -> None:
        if len(hosts) != len(ports):
            raise WazuhIndexerError(
                2001,
                extra_message="Hosts and ports lists must have the same length"
            )

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
        self.max_version_components = MaxVersionIndex(client=self._client)

    def _get_opensearch_client(self) -> AsyncOpenSearch:
        """
        Configure and initialize the AsyncOpenSearch client.

        Returns
        -------
        AsyncOpenSearch
            An instance of the OpenSearch asynchronous client.

        Raises
        ------
        WazuhIndexerError
            If credentials ('user' and 'password') are missing.
        WazuhIndexerError
            If SSL is enabled but certificate paths are missing.
        """
        nodes = [{"host": h, "port": p}
                 for h, p in zip(self.hosts, self.ports)]
        parameters = {
            "hosts": nodes,
            "http_compress": True,
            "use_ssl": self.use_ssl,
            "verify_certs": self.verify_certs,
            "ca_certs": self.ca_certs,
            "timeout": 30,
        }

        if self.user and self.password:
            parameters["http_auth"] = (self.user, self.password)
        else:
            raise WazuhIndexerError(
                2201, extra_message="'user' and 'password' are required"
            )

        if self.use_ssl:
            if self.client_cert and self.client_key:
                parameters.update(
                    {"client_cert": self.client_cert,
                     "client_key": self.client_key}
                )
            else:
                raise WazuhIndexerError(
                    2201,
                    extra_message="SSL certificates paths missing",
                )

        return AsyncOpenSearch(**parameters)

    async def connect(self) -> None:
        """
        Establish a connection to the Wazuh Indexer and verify its status.

        Returns
        -------
        dict
            The response from the Indexer `info()` call.

        Raises
        ------
        WazuhIndexerError
            If there is a connection error, transport error, SSL failure,
            or improper configuration.
        """
        getLogger("wazuh").debug("Connecting to the indexer client.")
        try:
            return await self._client.info()
        except (ConnectionError, TransportError) as e:
            raise WazuhIndexerError(2200, extra_message=e.error)
        except ssl.SSLError as e:
            raise WazuhIndexerError(2200, extra_message=e.reason)
        except ImproperlyConfigured as e:
            raise WazuhIndexerError(
                2200,
                extra_message=f"{e}. Check your indexer configuration"
                              f"and SSL certificates",
            )

    async def close(self) -> None:
        """
        Close the Wazuh Indexer client session asynchronously.
        """
        getLogger("wazuh").debug("Closing the indexer client session.")
        await self._client.close()


async def create_indexer(retries: int = 5,
                         backoff: int = 1,
                         **kwargs) -> Indexer:
    """
    Create and initialize the Indexer instance with a retry mechanism.

    This function attempts to connect to the indexer multiple times using
    exponential backoff with jitter to handle transient network issues.

    Parameters
    ----------
    retries : int, optional
        Maximum number of reconnection attempts, by default 5.
    backoff : int, optional
        Base wait time in seconds for exponential backoff, by default 1.
    **kwargs : dict
        Arguments passed directly to the `Indexer` constructor
        (hosts, ports, user, password, etc.).

    Returns
    -------
    Indexer
        An initialized and connected Indexer instance.

    Raises
    ------
    WazuhIndexerError
        If the maximum number of retries is reached without a
        successful connection.
    """
    indexer = Indexer(**kwargs)

    for attempt in range(retries + 1):
        try:
            await indexer.connect()
            return indexer
        except WazuhIndexerError as e:
            if attempt == retries:
                await indexer.close()
                raise e

            # Exponential backoff with jitter to avoid "thundering herd"
            wait_time = (backoff * 2**attempt) + random.random()
            getLogger("wazuh").warning(
                f"Connection failed (Attempt {attempt+1}/{retries+1})."
                f" Retrying in {wait_time:.2f}s..."
            )
            await sleep(wait_time)


@asynccontextmanager
async def get_indexer_client() -> AsyncIterator[Indexer]:
    """
    Context manager to create, yield, and automatically close
    an indexer client.

    This utility fetches configuration from the Wazuh OSSEC config and
    keystore before initializing the client.

    Yields
    ------
    Indexer
        The initialized Indexer client instance.

    Raises
    ------
    WazuhIndexerError
        If initialization or connection fails.
    """
    ossec_config = get_ossec_conf(section="indexer")
    indexer_section = ossec_config.get("indexer", {})
    ssl_config = indexer_section.get("ssl", {})

    ks_client = KeystoreClient(getLogger("wazuh"))
    try:
        indexer_user = ks_client.get("indexer", "username")["value"]
        indexer_pass = ks_client.get("indexer", "password")["value"]
    finally:
        ks_client.disconnect()

    hosts_raw = indexer_section.get("hosts", [])
    parsed_urls = [urlparse(h) for h in hosts_raw]

    list_of_hosts = [p.hostname for p in parsed_urls]
    list_of_ports = [p.port for p in parsed_urls]

    client = await create_indexer(
        hosts=list_of_hosts,
        ports=list_of_ports,
        user=indexer_user,
        password=indexer_pass,
        use_ssl=True,
        verify_certs=True,
        retries=3,
        client_cert_path=ssl_config["certificate"][0],
        client_key_path=ssl_config["key"][0],
        ca_certs_path=ssl_config["certificate_authorities"][0]["ca"][0],
    )

    try:
        yield client
    finally:
        await client.close()
