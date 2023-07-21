from typing import Any

class EngineMock:

    graph = dict()

    def get_graph_resource(self, policy: str, graph_type: str) -> dict[str, Any]:
        return self.graph[policy]

ENGINE = EngineMock()


def get_graph_resource(policy: str, graph_type: str) -> dict[str, Any]:
    """Get a resource from the graph..

    Parameters
    ----------
    policy : str
        Name of the policy.
    graph_type : str
        Type of graph.

    Returns
    -------
    dict[str, Any]
        A dictionary with the status, error and content.
    """
    # TODO: use socket to send the command instead of the mock
    resp = {'status': 'OK', 'error': None}
    try:
        resp['content'] = ENGINE.get_graph_resource(policy=policy, graph_type=graph_type)
    except Exception as exc:
        resp = {'status': 'ERROR', 'error': f'The specified graph resource does not exist: {exc}'}

    return resp
