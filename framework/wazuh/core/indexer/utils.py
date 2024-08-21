from typing import Iterator

from wazuh.core.indexer.base import IndexerKey


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
    return [item[IndexerKey._ID] for item in get_source_items(search_result)]
