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
from wazuh.core.exception import WazuhException, WazuhIndexerError
from wazuh.core.indexer.credential_manager import KeystoreClient
from wazuh.core.indexer.max_version_components import MaxVersionIndex


class Indexer:
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
        password: str = "", # nosec B107
        use_ssl: bool = True,
        client_cert_path: str = "",
        client_key_path: str = "",
        verify_certs: bool = True,
        ca_certs_path: str = "",
    ) -> None:
        if len(hosts) != len(ports):
            raise WazuhIndexerError(
                2001, extra_message="Hosts and ports lists must have the same length"
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
        nodes = [{"host": h, "port": p} for h, p in zip(self.hosts, self.ports)]
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
                    {"client_cert": self.client_cert, "client_key": self.client_key}
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


async def create_indexer(retries: int = 5, backoff: int = 1, **kwargs) -> Indexer:
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
            wait_time = (backoff * 2**attempt) + random.random() # nosec B311
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
    ConfigurationError
        If configuration is missing or malformed.
    CredentialsError
        If credentials are missing or invalid.
    """
    MAX_RETRIES = 3
    try:
        ossec_config = get_ossec_conf(section="indexer")
        if not ossec_config:
            raise WazuhException(
                code=1002, message="Missing indexer configuration in OSSEC config"
            )
    except Exception as e:
        raise WazuhException(
            code=1003, message=f"Failed to parse OSSEC configuration: {e}"
        )

    indexer_section = ossec_config.get("indexer", {})
    if not indexer_section:
        raise WazuhException(
            code=1004, message="Empty indexer section in configuration"
        )

    ssl_config = indexer_section.get("ssl", {})
    if not ssl_config:
        raise WazuhException(code=1005, message="Missing SSL configuration")

    try:
        with KeystoreClient() as ks_client:
            try:
                user_response = ks_client.get("indexer", "username")
                pass_response = ks_client.get("indexer", "password")
            except KeyError as e:
                raise WazuhException(
                    code=1006, message=f"Missing credential entry in keystore: {e}"
                )
            except Exception as e:
                raise WazuhException(
                    code=1007, message=f"Keystore operation failed: {e}"
                )

            indexer_user = user_response.get("value") if user_response else None
            indexer_pass = pass_response.get("value") if pass_response else None

            if not indexer_user:
                raise WazuhException(
                    code=1008, message="Empty or missing username in keystore"
                )
            if not indexer_pass:
                raise WazuhException(
                    code=1009, message="Empty or missing password in keystore"
                )
    except WazuhException:
        raise
    except Exception as e:
        raise WazuhException(
            code=1010, message=f"Failed to retrieve indexer credentials: {e}"
        )

    # Parse host URLs
    hosts_raw = indexer_section.get("hosts", [])
    if not hosts_raw:
        raise WazuhException(
            code=1011, message="No hosts specified in indexer configuration"
        )

    try:
        parsed_urls = [urlparse(h) for h in hosts_raw]
        list_of_hosts = []
        list_of_ports = []

        for i, p in enumerate(parsed_urls):
            if not p.hostname:
                raise WazuhException(
                    code=1012,
                    message=f"Invalid host URL at position {i}: {hosts_raw[i]}",
                )
            list_of_hosts.append(p.hostname)
            list_of_ports.append(p.port)
    except Exception as e:
        raise WazuhException(code=1013, message=f"Failed to parse host URLs: {e}")

    # Validate SSL certificate paths
    required_cert_paths = [
        ("client_cert", ssl_config.get("certificate", [])),
        ("client_key", ssl_config.get("key", [])),
        ("ca_certs", ssl_config.get("certificate_authorities", [{}])[0].get("ca", [])),
    ]

    for cert_name, cert_path_list in required_cert_paths:
        if not cert_path_list or not cert_path_list[0]:
            raise WazuhException(
                code=1014, message=f"Missing or empty {cert_name} path"
            )

    # Create indexer client
    try:
        client = await create_indexer(
            hosts=list_of_hosts,
            ports=list_of_ports,
            user=indexer_user,
            password=indexer_pass,
            use_ssl=True,
            verify_certs=True,
            retries=MAX_RETRIES,
            client_cert_path=ssl_config["certificate"][0],
            client_key_path=ssl_config["key"][0],
            ca_certs_path=ssl_config["certificate_authorities"][0]["ca"][0],
        )
    except Exception as e:
        raise WazuhException(code=1015, message=f"Failed to create indexer client: {e}")

    try:
        yield client
    except Exception as e:
        getLogger("wazuh").logger.error(f"Error in indexer client context: {e}")
        raise
    finally:
        try:
            await client.close()
        except Exception as e:
            getLogger("wazuh").logger.warning(
                f"Failed to close indexer client gracefully: {e}"
            )
