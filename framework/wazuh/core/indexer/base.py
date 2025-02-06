import logging
from enum import Enum
from typing import Any, Dict, List, Tuple

from opensearchpy import AsyncOpenSearch

POST_METHOD = 'POST'


class IndexerKey(str, Enum):
    """Opensearch API request fields keys."""

    _INDEX = '_index'
    _ID = '_id'
    _SOURCE = '_source'
    _DOCUMENTS = '_documents'
    ID = 'id'
    DOC = 'doc'
    MATCH = 'match'
    MATCH_ALL = 'match_all'
    QUERY = 'query'
    QUERY_STRING = 'query_string'
    CREATE = 'create'
    DELETE = 'delete'
    INDEX = 'index'
    UPDATE = 'update'
    BOOL = 'bool'
    MUST = 'must'
    HITS = 'hits'
    TOTAL = 'total'
    DELETED = 'deleted'
    FAILURES = 'failures'
    WILDCARD = 'wildcard'
    BODY = 'body'
    TERMS = 'terms'
    TERM = 'term'
    CONFLICTS = 'conflicts'
    ITEMS = 'items'
    IDS = 'ids'
    PAINLESS = 'painless'
    RANGE = 'range'
    LTE = 'lte'
    NOW = 'now'
    FILTER = 'filter'
    RESULT = 'result'
    STATUS = 'status'
    ERROR = 'error'
    REASON = 'reason'


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
    for k, v in items:
        if v is not None:
            new_dict[k] = v

    return new_dict
