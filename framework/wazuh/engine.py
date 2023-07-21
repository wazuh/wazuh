from wazuh.core.results import WazuhResult
from wazuh.core import engine
from wazuh.core.exception import WazuhError
from wazuh.core.InputValidator import InputValidator


def get_graph_resource(policy: str, graph_type: str) -> WazuhResult:
    """Get a resource from the graph.

    Parameters
    ----------
    policy : str
        Name of the policy.
    graph_type : str
        Type of graph.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the configuration.
    """
    data = engine.get_graph_resource(policy, graph_type)
    return WazuhResult({'data': data})