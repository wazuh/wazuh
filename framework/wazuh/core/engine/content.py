import json
from typing import List, Dict

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat, Status

# --- In-memory stub so GET returns what POST/PUT/DELETE did (until #31021) ---
_STUB_STORE: Dict[str, Dict[str, Dict[str, Dict]]] = {
    PolicyType.TESTING.value:  {ResourceType.KVDB.value: {}},
    PolicyType.PRODUCTION.value: {ResourceType.KVDB.value: {}},
}
# ----------------------------------------------------------------------------


class ContentModule(BaseModule):
    """Module to interact with Engine content resources."""

    async def create_resource(self, type: ResourceType, format: ResourceFormat, content: str, policy_type: PolicyType) -> dict:
        """Create a new content resource.
        Parameters
        ----------
        type : ResourceType
            The type of the resource to create.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The content of the resource.
        policy_type : PolicyType
            The policy type for the resource.
        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return {'status': 'OK', 'error': None}

    async def get_resources(self, type: ResourceType, name_list: List[str], policy_type: PolicyType) -> dict:
        """Retrieve a list of content resources.
        Parameters
        ----------
        type : ResourceType
            The type of resources to retrieve.
        name_list : List[str]
            List of resource names to retrieve.
        policy_type : PolicyType
            The policy type for the resources.
        Returns
        -------
        dict
            The JSON response from the engine.
        Raises
        ------
        WazuhError
            If resource retrieval fails (code 8004).
        """
        content: List[Dict] = []
        if type == ResourceType.KVDB:
            bucket = _STUB_STORE.get(policy_type.value, {}).get(ResourceType.KVDB.value, {})
            if name_list:
                for _id in name_list:
                    item = bucket.get(_id)
                    if item:
                        content.append(item)
            else:
                content = list(bucket.values())

        return {'status': 'OK', 'error': None, 'content': content}

    async def update_resource(self, name: str, content: str, policy_type: PolicyType) -> dict:
        """Update an existing content resource.
        Parameters
        ----------
        name : str
            The name of the resource.
        content : str
            The new content of the resource.
        policy_type : PolicyType
            The policy type for the resource.
        Returns
        -------
        dict
            The JSON response from the engine.
        """
        try:
            payload = json.loads(content)
        except Exception:
            payload = {'_raw': content}

        bucket = _STUB_STORE[policy_type.value][ResourceType.KVDB.value]
        bucket[name] = {
            'type': ResourceType.KVDB.value,
            'id': name,
            'name': name,
            'integration_id': None,
            'status': Status.ENABLED.value,
            'content': payload
        }
        return {'status': 'OK', 'error': None}

    async def delete_resource(self, name: str, policy_type: PolicyType) -> dict:
        """Delete a content resource.
        Parameters
        ----------
        name : str
            The name of the resource to delete.
        policy_type : PolicyType
            The policy type for the resource.
        Returns
        -------
        dict
            The JSON response from the engine.
        """
        _STUB_STORE[policy_type.value][ResourceType.KVDB.value].pop(name, None)
        return {'status': 'OK', 'error': None}
