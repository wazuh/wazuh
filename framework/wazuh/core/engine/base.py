import logging
from enum import Enum
from typing import Any, Dict, List, Tuple

from httpx import AsyncClient

APPLICATION_JSON = 'application/json'
APPLICATION_NDJSON = 'application/x-ndjson'


class BaseModule:
    """Base class to interact with Engine modules."""

    MODULE = None
    API_URL = 'http://localhost'

    def __init__(self, client: AsyncClient) -> None:
        self._client = client
        self._logger = logging.getLogger('wazuh')


def convert_enums(items: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Convert enums to their actual values and remove None values from a dictionary.

    Parameters
    ----------
    items
        List of tuples to evaluate.

    Returns
    -------
    Dict[str, Any]
        Dictionary with enums values and no None values.
    """
    new_dict = {}
    for k, v in items:
        if isinstance(v, Enum):
            new_dict[k] = v.value
        elif v is not None:
            new_dict[k] = v

    return new_dict
