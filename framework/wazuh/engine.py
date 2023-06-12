from wazuh.core.results import WazuhResult
from wazuh.core import engine

def get_runtime_config(name: str = None) -> WazuhResult:
    """Get the runtime configuration of the manager.

    Parameters
    ----------
    name : str
        Name of the configuration option.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    # TODO: sorting, filters, etc.
    data = engine.get_runtime_config(name)
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
    data = engine.update_runtime_config(name, content, save)
    return WazuhResult({'data': data})
