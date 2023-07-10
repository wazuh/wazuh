from wazuh.core.results import WazuhResult
from wazuh.core import engine
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.utils import process_array
from wazuh.core.InputValidator import InputValidator


def get_runtime_config(name: str = None, q: str = None, select: str = None, sort: str = None, search: str = None,
                       offset: int = 0, limit: int = None) -> WazuhResult:
    """Get the runtime configuration of the manager.

    Parameters
    ----------
    name : str
        Name of the configuration option.
    q : str
        Query to filter agents by.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma).
        Use +/- at the beginning to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    if name and not InputValidator().check_name(name):
        raise WazuhError(1129)

    data = engine.get_runtime_config(name)
    data = process_array(data, q=q, select=select, sort_by=sort, search_text=search, offset=offset, limit=limit)
    return WazuhResult({'data': data})

def update_runtime_config(name: str, content: str, save: bool = False) -> WazuhResult:
    """Update the runtime configuration of the manager.

    Parameters
    ----------
    name : str
        Name of the configuration option.
    content : str
        Value of the configuration option.
    save : bool
        Save the configuration to disk.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    if not InputValidator().check_name(name):
        raise WazuhError(1129)

    try:
        engine.update_runtime_config(name, content, save)
    except Exception as e:
        raise WazuhInternalError(1005, extra_message=str(e))

    return WazuhResult({'message': f"Engine configuration '{name}' updated."})
