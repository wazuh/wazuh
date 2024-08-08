from .constants import HITS_KEY, SOURCE_KEY


def get_source_items(search_result: dict) -> list:
    """Extract the elements from a search query.

    Parameters
    ----------
    search_result : dict
        Data to extract the elements.

    Returns
    -------
    list
        Obtained items.
    """
    return [item[SOURCE_KEY] for item in search_result[HITS_KEY][HITS_KEY]]