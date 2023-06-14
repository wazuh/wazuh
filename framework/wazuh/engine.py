from wazuh.core.results import WazuhResult
from wazuh.core import engine

def add_integration_policy(policy: str, integration: str) -> WazuhResult:
    """Add an integration to a policy in the catalog.
    Parameters
    ----------
    policy : str
        Name of the policy.
    integration: str
        Name of the integration.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    # TODO: sorting, filters, etc.
    data = engine.add_integration_policy(policy, integration)
    return WazuhResult({'data': data})

def remove_integration_policy(policy: str, integration: str) -> WazuhResult:
    """Remove an integration from a policy in the catalog.
    Parameters
    ----------
    policy : str
        Name of the policy.
    integration: str
        Name of the integration.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    data = engine.remove_integration_policy(policy, integration)
    return WazuhResult({'data': data})