import os
from enum import Enum
from hashlib import pbkdf2_hmac
from typing import Any, Dict, Iterator, List, Tuple

from wazuh.core.indexer.base import IndexerKey

ITERATIONS = 100_000
HASH_ALGO = 'sha256'


def generate_salt() -> bytes:
    """Generate a random salt value.

    Returns
    -------
    bytes
        Random salt.
    """
    return os.urandom(16)


def hash_key(key: str, salt: bytes) -> str:
    """Hash the given key using the provided salt.

    Parameters
    ----------
    key : str
        Value to hash.
    salt : bytes
        Value to use within derivation function.

    Returns
    -------
    str
        The hashed key.
    """
    return pbkdf2_hmac(HASH_ALGO, key.encode('utf-8'), salt, ITERATIONS)


def get_source_items(search_result: dict) -> Iterator[str]:
    """Extract the elements from a search query.

    Parameters
    ----------
    search_result : dict
        Data to extract the elements.

    Yields
    ------
    Iterator[str]
        Obtained items.
    """
    for item in search_result[IndexerKey.HITS][IndexerKey.HITS]:
        yield item[IndexerKey._SOURCE]


def get_source_items_id(search_result: dict) -> list:
    """Extract the 'id' of the elements from a search query.

    Parameters
    ----------
    search_result : dict
        Data to extract the elements.

    Returns
    -------
    list
        Obtained id items.
    """
    return [item['id'] for item in get_source_items(search_result)]


def get_document_ids(search_result: dict) -> list:
    """Extract the documents IDs from a search query.

    Parameters
    ----------
    search_result : dict
        Data to extract the elements.

    Returns
    -------
    list
        Obtained id items.
    """
    document_ids = []
    for doc in search_result[IndexerKey.HITS][IndexerKey.HITS]:
        document_ids.append(doc[IndexerKey._ID])
    return document_ids


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
