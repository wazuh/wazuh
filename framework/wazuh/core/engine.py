from typing import Any

class EngineMock:

    policies: dict[str, list] = {}

    def add_integration_policy(self, policy: str, integration: str):
        try:
            self.policies[policy].append(integration)
        except:
            self.policies[policy] = [integration]

    def remove_integration_policy(self, policy: str, integration: str):
        self.policies[policy].remove(integration)

ENGINE = EngineMock()


def add_integration_policy(policy: str, integration: str) -> dict[str, Any]:
    """Get the runtime configuration of the manager.

    Parameters
    ----------
    policy : str
        Name of the policy.
    integration: str
        Name of the integration.

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.add_integration_policy(policy, integration)
    resp = {'status': 'OK', 'error': None}
    return resp

def remove_integration_policy(policy: str, integration: str) -> dict[str, Any]:
    """Get the runtime configuration of the manager.

    Parameters
    ----------
    policy : str
        Name of the policy.
    integration: str
        Name of the integration.

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.remove_integration_policy(policy, integration)
    resp = {'status': 'OK', 'error': None}
    return resp
