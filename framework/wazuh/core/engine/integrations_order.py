from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType


class IntegrationsOrderModule(BaseModule):
    """Module for managing integrations order resources in the Wazuh engine."""

    async def create_order(self, content: str, policy_type: PolicyType):
        """Create a new integrations order resource.

        Parameters
        ----------
        content : str
            The JSON string representing the integrations order.
        policy_type : PolicyType
            The policy type for the integrations order.

        Returns
        -------
        dict
            Dictionary with the status and error information.
        """
        return {'status': 'OK', 'error': None}

    async def get_order(self, policy_type: PolicyType):
        """Retrieve the integrations order resource.

        Parameters
        ----------
        policy_type : PolicyType
            The policy type for the integrations order.

        Returns
        -------
        dict
            Dictionary with the status, error information, and content.
        """
        return {'status': 'OK', 'error': None, 'content': []}

    async def delete_order(self, policy_type: PolicyType):
        """Delete the integrations order resource.

        Parameters
        ----------
        policy_type : PolicyType
            The policy type for the integrations order.

        Returns
        -------
        dict
            Dictionary with the status and error information.
        """
        return {'status': 'OK', 'error': None}
