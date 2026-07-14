import asyncio
import os
import random
import ssl
import threading
from asyncio import sleep
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from logging import getLogger
from os.path import isabs, join
from typing import AsyncIterator, List, Optional
from urllib.parse import urlparse

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import ImproperlyConfigured, TransportError
from wazuh.core import common
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.exception import WazuhIndexerError, IndexerUnavailableError
from wazuh.core.indexer.credential_manager import KeystoreClient
from wazuh.core.indexer.states_components import StatesIndex
from wazuh.core.indexer.metrics import MetricsIndex

MAX_RETRIES = 3
BACKOFF_TIMEOUT = 60

logger = getLogger("wazuh")


# ============================================================================
# Configuration and SSL Context Caching
# ============================================================================

_config_cache: Optional[dict] = None
_config_mtime: Optional[float] = None
_config_lock = asyncio.Lock()

# Thread lock for SSL context creation to prevent race conditions
_ssl_context_lock = threading.Lock()


async def _get_cached_indexer_config() -> dict:
    """
    Get indexer configuration with file modification time check.

    Caches the configuration to avoid repeated XML parsing on every
    indexer connection attempt. Cache is invalidated when the config
    file is modified.

    Returns
    -------
    dict
        Indexer configuration section from ossec.conf
    """
    global _config_cache, _config_mtime

    async with _config_lock:
        config_file = common.OSSEC_CONF

        try:
            current_mtime = os.path.getmtime(config_file)

            # Return cached config if file hasn't changed
            if _config_cache is not None and _config_mtime == current_mtime:
                return _config_cache

            # Read and cache configuration
            _config_cache = get_ossec_conf(section="indexer")
            _config_mtime = current_mtime
            logger.debug(f"Cached indexer configuration (mtime: {current_mtime})")
            return _config_cache

        except OSError as e:
            # File doesn't exist or can't read - fetch without caching
            logger.warning(f"Could not cache config file: {e}")
            return get_ossec_conf(section="indexer")


_ssl_context_cache: Optional[ssl.SSLContext] = None
_ssl_context_cache_key: Optional[tuple] = None


def _create_ssl_context(client_cert: str, client_key: str, ca_certs: str) -> ssl.SSLContext:
    """
    Create and cache SSL context for indexer connections.

    This prevents repeated reads of certificate files and the system CA bundle
    on every connection attempt. The SSL context is reused across all connection
    attempts, significantly reducing disk I/O during retry scenarios.

    Thread-safe: Uses a lock to prevent multiple threads from simultaneously
    creating SSL contexts during cache misses.

    Parameters
    ----------
    client_cert : str
        Path to client certificate file
    client_key : str
        Path to client key file
    ca_certs : str
        Path to CA certificate file

    Returns
    -------
    ssl.SSLContext
        Configured SSL context ready for use
    """
    global _ssl_context_cache, _ssl_context_cache_key

    cache_key = (client_cert, client_key, ca_certs)

    # Fast path: check cache without lock
    if _ssl_context_cache is not None and _ssl_context_cache_key == cache_key:
        return _ssl_context_cache

    # Slow path: acquire lock and create context
    with _ssl_context_lock:
        # Double-check after acquiring lock (another thread might have created it)
        if _ssl_context_cache is not None and _ssl_context_cache_key == cache_key:
            return _ssl_context_cache

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=ca_certs
        )
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        logger.debug("Created cached SSL context for indexer connections")

        _ssl_context_cache = context
        _ssl_context_cache_key = cache_key
        return context


# ============================================================================
# Circuit Breaker Pattern
# ============================================================================

class _IndexerCircuitBreaker:
    """
    Circuit breaker to prevent concurrent retry storms to indexer.

    When the indexer becomes unavailable, multiple tasks may attempt to
    connect simultaneously, each reading config and certificates repeatedly.
    This circuit breaker coordinates retry attempts to prevent excessive
    disk I/O during indexer failures.
    """

    _open_until: Optional[datetime] = None
    _lock = asyncio.Lock()
    BACKOFF_TIME = 60  # seconds before allowing retry after circuit opens

    @classmethod
    async def check(cls) -> None:
        """
        Check if circuit breaker allows connection attempt.

        Raises
        ------
        IndexerUnavailableError
            If circuit breaker is open (indexer recently failed)
        """
        async with cls._lock:
            if cls._open_until and datetime.now() < cls._open_until:
                wait_seconds = (cls._open_until - datetime.now()).total_seconds()
                raise IndexerUnavailableError(
                    2200,
                    extra_message=f"Circuit breaker open, retry in {wait_seconds:.0f}s"
                )

    @classmethod
    async def record_failure(cls) -> None:
        """Record indexer connection failure and open circuit breaker."""
        async with cls._lock:
            cls._open_until = datetime.now() + timedelta(seconds=cls.BACKOFF_TIME)
            logger.warning(f"Circuit breaker opened until {cls._open_until}")

    @classmethod
    async def record_success(cls) -> None:
        """Record successful connection and close circuit breaker."""
        async with cls._lock:
            if cls._open_until:
                logger.info("Circuit breaker closed - indexer connection restored")
            cls._open_until = None


def resolve_wazuh_path(path: str) -> str:
    """Resolve Wazuh-relative paths from the manager installation directory."""
    return path if isabs(path) else join(common.WAZUH_PATH, path)


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
    ssl_context : ssl.SSLContext, optional
        Pre-configured SSL context with certificates. Required when use_ssl is True.
        The SSL context should already have verification settings configured.

    Attributes
    ----------
    hosts : List[str]
        The list of configured hosts.
    ports : List[int]
        The list of configured ports.
    states : StatesIndex
        Component to manage index versioning.
    metrics : MetricsIndex
        Component to handle metrics snapshot bulk indexing.

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
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        if len(hosts) != len(ports):
            raise WazuhIndexerError(
                2001, None, "Hosts and ports lists must have the same length"
            )

        self.hosts = hosts
        self.user = user
        self.password = password
        self.ports = ports
        self.use_ssl = use_ssl
        self.ssl_context = ssl_context

        self._client = self._get_opensearch_client()
        self.states = StatesIndex(client=self._client)
        self.metrics = MetricsIndex(client=self._client)

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
            If SSL is enabled but SSL context is missing.
        """
        nodes = [{"host": h, "port": p} for h, p in zip(self.hosts, self.ports)]
        parameters = {
            "hosts": nodes,
            "http_compress": True,
            "use_ssl": self.use_ssl,
            "timeout": 30,
        }

        if self.user and self.password:
            parameters["http_auth"] = (self.user, self.password)
        else:
            raise WazuhIndexerError(
                2201, None, "'user' and 'password' are required"
            )

        if self.use_ssl:
            # Use cached SSL context (verification settings are already configured in the context)
            if self.ssl_context:
                parameters["ssl_context"] = self.ssl_context
            else:
                raise WazuhIndexerError(
                    2201,
                    None, "SSL context required for secure connections",
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
            return await self.healthcheck()
        except (ConnectionError, TransportError) as e:
            raise WazuhIndexerError(2200, None, e.error)
        except ssl.SSLError as e:
            raise WazuhIndexerError(2200, None, e.reason)
        except ImproperlyConfigured as e:
            raise WazuhIndexerError(
                2200,
                None, f"{e}. Check your indexer configuration and SSL certificates"
            )

    async def close(self) -> None:
        """
        Close the Wazuh Indexer client session asynchronously.
        """
        logger.debug("Closing the indexer client session.")
        await self._client.close()

    async def search(self, *args, **kwargs):
        """
        Perform a search query against the Wazuh Indexer.

        This method is a wrapper around the OpenSearch client's `search` method,
        allowing for direct query execution.

        Parameters
        ----------
        *args
            Positional arguments to pass to the OpenSearch client's `search` method.
        **kwargs
            Keyword arguments to pass to the OpenSearch client's `search` method.
        Returns
        -------
        dict
            The search results returned by the OpenSearch client.
        """
        return await self._client.search(*args, **kwargs)

    async def mget(self, *args, **kwargs):
        """
        Perform a multi-get query against the Wazuh Indexer.

        This method is a wrapper around the OpenSearch client's `mget` method,
        allowing for retrieval of multiple documents by ID.

        Parameters
        ----------
        *args
            Positional arguments to pass to the OpenSearch client's `mget` method.
        **kwargs
            Keyword arguments to pass to the OpenSearch client's `mget` method.
        Returns
        -------
        dict
            The multi-get results returned by the OpenSearch client.
        """
        return await self._client.mget(*args, **kwargs)

    async def healthcheck(self) -> bool:
        """Check the health of the Wazuh Indexer connection.

        Attempts to call the `info()` endpoint of the OpenSearch client.
        If the call succeeds, the method returns `None`. If any exception
        occurs (e.g., network issues, authentication failure), a
        `WazuhIndexerError` is raised with the appropriate error code and
        message.

        Raises
        ------
        WazuhIndexerError
            If the indexer is unreachable or does not respond correctly.
            The error code is `2200` and the message includes the original
            exception details.
        """
        try:
            await self._client.info()
        except Exception as e:
            raise WazuhIndexerError(2200, extra_message=f"Failed to create indexer client: {e}")


async def create_indexer(retries: int = MAX_RETRIES, backoff: int = BACKOFF_TIMEOUT, **kwargs) -> Indexer:
    """
    Create and initialize the Indexer instance with a retry mechanism.

    This function attempts to connect to the indexer multiple times using
    exponential backoff with jitter to handle transient network issues.

    Parameters
    ----------
    retries : int, optional
        Maximum number of reconnection attempts, by default 3.
    backoff : int, optional
        Base wait time in seconds for exponential backoff, by default 60.
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
        If the Indexer constructor receives invalid arguments (TypeError).
    IndexerUnavailableError
        If the maximum number of retries is reached without a successful connection.
    """
    try:
        indexer = Indexer(**kwargs)
    except TypeError as e:
        raise WazuhIndexerError(2201, extra_message=f"Invalid arguments for Indexer: Error:{e}") from e

    for attempt in range(retries + 1):
        try:
            await indexer.connect()
            await _IndexerCircuitBreaker.record_success()
            return indexer
        except WazuhIndexerError as e:
            if attempt == retries:
                await indexer.close()
                await _IndexerCircuitBreaker.record_failure()
                logger.warning(
                    f"Indexer service is unavailable after multiple connection attempts. Some functionality may be limited. "
                    f"Error: {e}. Verify indexer connectivity and configuration."
                )
                raise IndexerUnavailableError(
                    2200, extra_message=f"Indexer unavailable after {retries} retries. Error: {e}"
                ) from e

            # Exponential backoff with jitter to avoid "thundering herd"
            wait_time = (backoff * 2**attempt) + random.random() # nosec B311
            logger.warning(
                f"Connection attempt {attempt + 1} failed: {e}. Retrying in {wait_time:.2f} seconds..."
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
    ConfigurationError
        If configuration is missing or malformed.
    CredentialsError
        If credentials are missing or invalid.
    """
    # Check circuit breaker before attempting connection
    await _IndexerCircuitBreaker.check()

    try:
        # Use cached configuration
        wazuh_config = await _get_cached_indexer_config()
        if not wazuh_config:
            raise IndexerUnavailableError(
                code=2200, extra_message="Missing indexer configuration in Wazuh config"
            )
    except Exception as e:
        raise IndexerUnavailableError(
            code=2200, extra_message=f"Failed to parse Wazuh configuration: {e}"
        )

    indexer_section = wazuh_config.get("indexer", {})
    if not indexer_section:
        raise IndexerUnavailableError(
            code=2200, extra_message="Empty indexer section in configuration"
        )

    ssl_config = indexer_section.get("ssl", {})
    if not ssl_config:
        raise IndexerUnavailableError(code=2200, extra_message="Missing SSL configuration")

    try:
        with KeystoreClient() as ks_client:
            try:
                user_response = ks_client.get("indexer", "username")
                pass_response = ks_client.get("indexer", "password")
            except KeyError as e:
                raise IndexerUnavailableError(
                    code=2201, extra_message=f"Missing credential entry in keystore: {e}"
                )
            except Exception as e:
                raise IndexerUnavailableError(
                    code=2201, extra_message=f"Keystore operation failed: {e}"
                )

            indexer_user = user_response.get("value") if user_response else None
            indexer_pass = pass_response.get("value") if pass_response else None

            if not indexer_user:
                raise IndexerUnavailableError(
                    code=2201, extra_message="Empty or missing username in keystore"
                )
            if not indexer_pass:
                raise IndexerUnavailableError(
                    code=2201, extra_message="Empty or missing password in keystore"
                )
    except IndexerUnavailableError:
        raise
    except Exception as e:
        raise IndexerUnavailableError(
            code=2201, extra_message=f"Failed to retrieve indexer credentials: {e}"
        )

    # Parse host URLs
    hosts_raw = indexer_section.get("hosts", [])
    if not hosts_raw:
        raise IndexerUnavailableError(
            code=2200, extra_message="No hosts specified in indexer configuration"
        )

    try:
        parsed_urls = [urlparse(h) for h in hosts_raw]
        list_of_hosts = []
        list_of_ports = []

        for i, p in enumerate(parsed_urls):
            if not p.hostname:
                raise IndexerUnavailableError(
                    code=2200,
                    extra_message=f"Invalid host URL at position {i}: {hosts_raw[i]}",
                )
            list_of_hosts.append(p.hostname)
            list_of_ports.append(p.port)
    except Exception as e:
        raise IndexerUnavailableError(code=2200, extra_message=f"Failed to parse host URLs: {e}")

    # Validate SSL certificate paths
    required_cert_paths = [
        ("client_cert", ssl_config.get("certificate", [])),
        ("client_key", ssl_config.get("key", [])),
        ("ca_certs", ssl_config.get("certificate_authorities", [{}])[0].get("ca", [])),
    ]

    for cert_name, cert_path_list in required_cert_paths:
        if not cert_path_list or not cert_path_list[0]:
            raise IndexerUnavailableError(
                code=2200, extra_message=f"Missing or empty {cert_name} path"
            )

    client_cert = resolve_wazuh_path(ssl_config["certificate"][0])
    client_key = resolve_wazuh_path(ssl_config["key"][0])
    ca_certs = resolve_wazuh_path(ssl_config["certificate_authorities"][0]["ca"][0])

    # Create cached SSL context to prevent repeated certificate file reads
    ssl_context = _create_ssl_context(client_cert, client_key, ca_certs)

    # Create indexer client with cached SSL context
    try:
        client = await create_indexer(
            hosts=list_of_hosts,
            ports=list_of_ports,
            user=indexer_user,
            password=indexer_pass,
            use_ssl=True,
            ssl_context=ssl_context,
        )
    except IndexerUnavailableError:
        raise
    except Exception as e:
        raise IndexerUnavailableError(code=2200, extra_message=f"Failed to create indexer client: {e}")

    try:
        yield client
    except Exception as e:
        logger.error(f"Error in indexer client context: {e}")
        raise
    finally:
        try:
            await client.close()
        except Exception as e:
            logger.warning(
                f"Failed to close indexer client gracefully: {e}"
            )
