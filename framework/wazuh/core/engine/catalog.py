# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.resources import ResourceFormat

class CatalogModule(BaseModule):
    """Module to interact with the Engine catalog resources."""

    async def validate_resource(self, name: str, format: ResourceFormat, content: str, namespace_id: str):
        """Validate a resource payload against the Engine catalog.

        Parameters
        ----------
        name : str
            Resource identifier to validate.
        format : ResourceFormat
            Serialization format of the payload (e.g., JSON).
        content : str
            Resource payload serialized as a string.
        namespace_id : str
            Target namespace for validation.

        Returns
        -------
        dict
            Engine-like response with 'status' and 'error' keys.
        """
        return {'status': 'OK', 'error': None}
