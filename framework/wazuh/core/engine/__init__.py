from contextlib import asynccontextmanager
from logging import getLogger
from typing import AsyncIterator

from httpx import AsyncClient, AsyncHTTPTransport, ConnectError, Timeout, TimeoutException, UnsupportedProtocol, \
    HTTPError
from wazuh.core.exception import WazuhEngineError

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

    async def close(self) -> None:
        """Close the Engine client."""
        await self._client.aclose()
    
    async def send(self, path: str, data: dict) -> dict:
        """Send a request to the engine.
        
        Parameters
        ----------
        path : str
            The API endpoint path to send the request to.
        data : dict
            The data to send in the request body.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        if not path.startswith('/'):
            path = f'/{path}'

        try:
            response = await self._client.post(
                url=f'http://localhost{path}',
                json=data,
                timeout=Timeout(DEFAULT_TIMEOUT)
            )
            response.raise_for_status()
        except (TimeoutException, UnsupportedProtocol, ConnectError) as e:
            raise WazuhEngineError(2800, extra_message=str(e))
        except HTTPError as e:
            raise WazuhEngineError(2803, extra_message=str(e))
        except Exception as e:
            raise WazuhEngineError(2804, extra_message=str(e))

        try:
            return response.json()
        except ValueError:
            raise WazuhEngineError(2805, extra_message=response.text)


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
