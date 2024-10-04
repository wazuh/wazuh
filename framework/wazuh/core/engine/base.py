import logging

from httpx import AsyncClient


class BaseModule:
    """Base class to interact with Engine modules."""

    MODULE = None
    API_URL_PREFIX = '/api/v1'

    def __init__(self, client: AsyncClient) -> None:
        self._client = client
        self._logger = logging.getLogger('wazuh')
