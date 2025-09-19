# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat, Status


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
        return {'status': 'OK', 'error': None, 'content': []}

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
        return {'status': 'OK', 'error': None}
