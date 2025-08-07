import logging

from httpx import AsyncClient, ConnectError, HTTPError, Timeout, TimeoutException, UnsupportedProtocol
from wazuh.core.exception import WazuhEngineError


DEFAULT_TIMEOUT = 5


class BaseModule:
    """Base class to interact with Engine modules."""

    MODULE = None

    def __init__(self, client: AsyncClient) -> None:
        self._client = client
        self._logger = logging.getLogger('wazuh')
    
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
