# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict, Tuple
from httpx import AsyncClient

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat, Resource


class ContentModule(BaseModule):
    """Module to interact with Engine content resources."""

    # In-memory storage: key = (resource_type, policy_type, resource_name)
    _db: Dict[Tuple[ResourceType, PolicyType, str], Resource] = {}

    def __init__(self, client: AsyncClient):
        super().__init__(client)

    async def create_resource(
        self, resource: Resource, type: ResourceType, format: ResourceFormat, policy_type: PolicyType
    ) -> dict:
        """Create a new content resource."""
        key = (type, policy_type, resource.name)
        if key in self._db:
            return {"status": "ERROR", "error": f"Resource '{resource.name}' already exists"}
        self._db[key] = resource
        return {"status": "OK", "error": None}

    async def get_resources(self, type: ResourceType, name: str, policy_type: PolicyType) -> dict:
        """Retrieve a list of content resources."""
        key = (type, policy_type, name)
        if key not in self._db:
            return {"status": "ERROR", "error": f"Resource '{name}' not found"}
        resource = self._db[key]
        return {"status": "OK", "error": None, "content": resource.to_dict()}

    async def update_resource(self, resource: Resource) -> dict:
        """Update an existing content resource."""
        updated = False
        for key, stored_resource in self._db.items():
            if stored_resource.name == resource.name:
                self._db[key] = resource
                updated = True
                break
        if not updated:
            return {"status": "ERROR", "error": f"Resource '{resource.name}' not found"}
        return {"status": "OK", "error": None}

    async def delete_resource(self, name: str, policy_type: PolicyType) -> dict:
        """Delete a content resource."""
        deleted = False
        for key in list(self._db.keys()):
            if key[1] == policy_type and key[2] == name:
                del self._db[key]
                deleted = True
        if not deleted:
            return {"status": "ERROR", "error": f"Resource '{name}' not found"}
        return {"status": "OK", "error": None}
