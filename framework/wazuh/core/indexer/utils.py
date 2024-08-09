from typing import Iterator

from .constants import HITS_KEY, ID_KEY, SOURCE_KEY


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

    for item in search_result[HITS_KEY][HITS_KEY]:
        yield item[SOURCE_KEY]


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
    return [item[ID_KEY] for item in get_source_items(search_result)]
