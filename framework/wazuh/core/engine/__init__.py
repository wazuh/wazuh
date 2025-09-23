from contextlib import contextmanager
from logging import getLogger
from typing import Iterator
import asyncio

from httpx import AsyncClient, AsyncHTTPTransport, ConnectError, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.exception import WazuhEngineError

from wazuh.core.engine.catalog import CatalogModule
from wazuh.core.engine.content import ContentModule

logger = getLogger('wazuh')

ENGINE_API_SOCKET_PATH = '/var/ossec/queue/sockets/engine-api'
DEFAULT_RETRIES = 5
DEFAULT_TIMEOUT = 5


class Engine:
    """Wazuh Engine API client."""

    def __init__(
        self,
        socket_path: str = ENGINE_API_SOCKET_PATH,
        retries: int = DEFAULT_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        transport = AsyncHTTPTransport(uds=socket_path, retries=retries)
        self._client = AsyncClient(transport=transport, timeout=Timeout(timeout))

        # Register Engine modules here
        self.catalog = CatalogModule(self._client)
        self.content = ContentModule(self._client)

    def run(self, coro):
        """Run an async coroutine and return its result (sync helper)."""
        return asyncio.get_event_loop().run_until_complete(coro)

    async def close(self) -> None:
        """Close the Engine client."""
        await self._client.aclose()


@contextmanager
def get_engine_client() -> Iterator[Engine]:
    """Create and return the engine client.

    Returns
    -------
    AsyncIterator[Engine]
        Engine client iterator.
    """
    client = Engine()

    try:
        yield client
    except TimeoutException:
        raise WazuhEngineError(2800)
    except UnsupportedProtocol:
        raise WazuhEngineError(2801)
    except ConnectError:
        raise WazuhEngineError(2802)
    finally:
        # ensure the async close is executed from sync code
        try:
            client.run(client.close())
        except Exception:
            pass
