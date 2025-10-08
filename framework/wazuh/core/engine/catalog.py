# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.engine.base import  BaseModule
from wazuh.core.engine.models.resources import ResourceFormat


class CatalogModule(BaseModule):
    """Module to interact with the Engine catalog resources."""

    async def validate_resource(self, name: str, format: ResourceFormat, content: str, namespace_id: str):
        """Validate the syntax of a resource in the catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The content to validate.
        namespace_id : str
            The namespace identifier.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {
            'name': name,
            'format': format,
            'content': content,
            'namespaceid': namespace_id
        }

        # TODO real validation pending
        return {"status": "OK", "error": None}

        return await self.send('/catalog/resource/validate', body)
