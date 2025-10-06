# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from typing import Dict, Tuple
from httpx import AsyncClient

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat, Resource


class ContentModule(BaseModule):
    """Module to interact with Engine content resources (thread-safe shared version)."""

    # Shared in-memory storage: key = (resource_type, policy_type, resource_name)
    _db: Dict[Tuple[ResourceType, PolicyType, str], Resource] = {}

    # Shared lock for thread-safety across all instances
    _lock = asyncio.Lock()

    def __init__(self, client: AsyncClient):
        super().__init__(client)

    async def create_resource(
        self, resource: Resource, type: ResourceType, format: ResourceFormat, policy_type: PolicyType
    ) -> dict:
        """Create a new content resource."""
        key = (type, policy_type, resource.name)
        async with self._lock:
            if key in self._db:
                return {"status": "ERROR", "error": f"Resource '{resource.name}' already exists"}
            self._db[key] = resource
        return {"status": "OK", "error": None}

    async def get_resources(self, type: ResourceType, name: str, policy_type: PolicyType) -> dict:
        """Retrieve a list of content resources."""
        key = (type, policy_type, name)
        async with self._lock:
            if key not in self._db:
                return {"status": "ERROR", "error": f"Resource '{name}' not found"}
            resource = self._db[key]
        return {"status": "OK", "error": None, "content": resource.to_dict()}

    async def update_resource(
        self, resource: Resource, type: ResourceType, format: ResourceFormat, policy_type: PolicyType
    ) -> dict:
        """Update an existing content resource."""
        key = (type, policy_type, resource.name)
        async with self._lock:
            if key not in self._db:
                return {"status": "ERROR", "error": f"Resource '{resource.name}' not found"}
            self._db[key] = resource
        return {"status": "OK", "error": None}

    async def delete_resource(self, name: str, policy_type: PolicyType) -> dict:
        """Delete a content resource."""
        async with self._lock:
            keys_to_delete = [key for key in self._db if key[1] == policy_type and key[2] == name]
            if not keys_to_delete:
                return {"status": "ERROR", "error": f"Resource '{name}' not found"}
            for key in keys_to_delete:
                del self._db[key]
        return {"status": "OK", "error": None}
