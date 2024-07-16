import logging

from opensearchpy import AsyncOpenSearch


class BaseIndex:
    """Base class to interact with indexes."""

    INDEX = None

    def __init__(self, client: AsyncOpenSearch) -> None:
        self._client = client
        self._logger = logging.getLogger('wazuh')
