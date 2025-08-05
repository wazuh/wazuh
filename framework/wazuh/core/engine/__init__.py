from contextlib import asynccontextmanager
from logging import getLogger
from typing import AsyncIterator

from httpx import AsyncClient, AsyncHTTPTransport, ConnectError, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.exception import WazuhEngineError

logger = getLogger('wazuh')

ENGINE_API_SOCKET_PATH = '/var/ossec/queue/sockets/engine-api'
DEFAULT_RETRIES = 5
DEFAULT_TIMEOUT = 1


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

    async def close(self) -> None:
        """Close the Engine client."""
        await self._client.aclose()


@asynccontextmanager
async def get_engine_client() -> AsyncIterator[Engine]:
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
        await client.close()
