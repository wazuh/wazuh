import logging
from typing import Any, Dict, List, Tuple

from opensearchpy import AsyncOpenSearch


class BaseIndex:
    """Base class to interact with indexes."""

    INDEX = None

    def __init__(self, client: AsyncOpenSearch) -> None:
        self._client = client
        self._logger = logging.getLogger('wazuh')


def remove_empty_values(items: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Remove empty values from a dictionary.

    Parameters
    ----------
    items
        List of tuples to evaluate.
    
    Returns
    -------
    Dict[str, Any]
        Dictionary without None values.
    """
    new_dict = {}
    for (k, v) in items:
        if v is not None:
            new_dict[k] = v

    return new_dict
