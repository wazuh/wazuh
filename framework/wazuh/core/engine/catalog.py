# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.engine.base import BaseModule


class CatalogModule(BaseModule):
    """Module to interact with the Engine catalog resources."""

    async def validate_resource(self, id_: str, content: str, namespace_id: str):
        """Validate the syntax of a resource in the catalog.

        Parameters
        ----------
        id_ : str
            The id of the resource.
        content : str
            The content to validate.
        namespace_id : str
            The namespace identifier.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {"id": id_, "content": content, "namespaceid": namespace_id}

        # TODO real validation pending
        return {"status": "OK", "error": None}

        return await self.send("/catalog/resource/validate", body)
