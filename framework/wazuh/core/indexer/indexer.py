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
                2001, None, "Hosts and ports lists must have the same length"
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
                2201, None, "'user' and 'password' are required"
            )

        if self.use_ssl:
            if self.client_cert and self.client_key:
                parameters.update(
                    {"client_cert": self.client_cert, "client_key": self.client_key}
                )
            else:
                raise WazuhIndexerError(
                    2201, None, "SSL certificates paths missing"
                )

        return AsyncOpenSearch(**parameters)

    async def connect(self) -> None:
        try:
            return await self._client.info()
        except (ConnectionError, TransportError) as e:
            raise WazuhIndexerError(2200, None, e.error)
        except ssl.SSLError as e:
            raise WazuhIndexerError(2200, None, e.reason)
        except ImproperlyConfigured as e:
            raise WazuhIndexerError(
                2200, None, f"{e}. Check your indexer configuration and SSL certificates"
            )

    async def close(self) -> None:
        getLogger("wazuh").debug("Closing the indexer client session.")
        await self._client.close()


async def create_indexer(retries: int = 5, backoff: int = 1, **kwargs) -> Indexer:
    indexer = Indexer(**kwargs)

    for attempt in range(retries + 1):
        try:
            await indexer.connect()
            return indexer
        except WazuhIndexerError as e:
            if attempt == retries:
                await indexer.close()
                raise e
            wait_time = (backoff * 2**attempt) + random.random()
            await sleep(wait_time)


@asynccontextmanager
async def get_indexer_client() -> AsyncIterator[Indexer]:
    MAX_RETRIES = 3
    try:
        wazuh_config = get_ossec_conf(section="indexer")
        if not wazuh_config:
            raise WazuhException(1002, "Missing indexer configuration in Wazuh config")
    except Exception as e:
        raise WazuhException(1003, f"Failed to parse Wazuh configuration: {e}")

    indexer_section = wazuh_config.get("indexer", {})
    if not indexer_section:
        raise WazuhException(1004, "Empty indexer section in configuration")

    ssl_config = indexer_section.get("ssl", {})
    if not ssl_config:
        raise WazuhException(1005, "Missing SSL configuration")

    try:
        with KeystoreClient() as ks_client:
            try:
                user_response = ks_client.get("indexer", "username")
                pass_response = ks_client.get("indexer", "password")
            except KeyError as e:
                raise WazuhException(1006, f"Missing credential entry in keystore: {e}")
            except Exception as e:
                raise WazuhException(1007, f"Keystore operation failed: {e}")

            indexer_user = user_response.get("value") if user_response else None
            indexer_pass = pass_response.get("value") if pass_response else None

            if not indexer_user:
                raise WazuhException(1008, "Empty or missing username in keystore")
            if not indexer_pass:
                raise WazuhException(1009, "Empty or missing password in keystore")
    except WazuhException:
        raise
    except Exception as e:
        raise WazuhException(1010, f"Failed to retrieve indexer credentials: {e}")

    hosts_raw = indexer_section.get("hosts", [])
    if not hosts_raw:
        raise WazuhException(1011, "No hosts specified in indexer configuration")

    try:
        parsed_urls = [urlparse(h) for h in hosts_raw]
        list_of_hosts = []
        list_of_ports = []

        for i, p in enumerate(parsed_urls):
            if not p.hostname:
                raise WazuhException(1012, f"Invalid host URL at position {i}: {hosts_raw[i]}")
            list_of_hosts.append(p.hostname)
            list_of_ports.append(p.port)
    except Exception as e:
        raise WazuhException(1013, f"Failed to parse host URLs: {e}")

    required_cert_paths = [
        ("client_cert", ssl_config.get("certificate", [])),
        ("client_key", ssl_config.get("key", [])),
        ("ca_certs", ssl_config.get("certificate_authorities", [{}])[0].get("ca", [])),
    ]

    for cert_name, cert_path_list in required_cert_paths:
        if not cert_path_list or not cert_path_list[0]:
            raise WazuhException(1014, f"Missing or empty {cert_name} path")

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
        raise WazuhException(1015, f"Failed to create indexer client: {e}")

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
