import asyncio
from typing import Dict

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType


class IntegrationsOrderModule(BaseModule):
    """Module for managing integrations order resources in the Wazuh engine."""

    # Shared in-memory storage: key = (resource_type, policy_type, resource_id)
    _db: Dict[PolicyType, str] = {}

    # Shared lock for thread-safety across all instances
    _lock = asyncio.Lock()

    async def create_order(self, content: Dict, policy_type: PolicyType):
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
        async with self._lock:
            if policy_type in self._db:
                return {"status": "ERROR", "error": "Integration order already exists"}
            self._db[policy_type] = content
        return {"status": "OK", "error": None}
    
    async def update_order(self, content: Dict, policy_type: PolicyType):
        """Update integrations order resource.

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
        async with self._lock:
            self._db[policy_type] = content
        return {"status": "OK", "error": None}

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
        async with self._lock:
            if policy_type not in self._db:
                return {"status": "ERROR", "error": "Integration order not found"}
            resource = self._db[policy_type]
        return {"status": "OK", "error": None, "content": resource}

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
        async with self._lock:
            if policy_type not in self._db:
                return {"status": "ERROR", "error": "Integration order not found"}
            del self._db[policy_type]
        return {"status": "OK", "error": None}

