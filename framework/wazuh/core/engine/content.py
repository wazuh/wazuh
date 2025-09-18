# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat


class ContentModule(BaseModule):
    """Module to interact with Engine content resources."""

    async def create_resource(self, type: ResourceType, format: ResourceFormat, content: str, policy_type: PolicyType):
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

    async def update_resource(self, name: str, format: ResourceFormat, content: str, policy_type: PolicyType):
        """Update an existing content resource.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
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

    async def delete_resource(self, name: str, policy_type: PolicyType):
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
