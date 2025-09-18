from enum import Enum

from wazuh.core.engine.base import  BaseModule
from wodles.gcloud import integration


class ResourceType(Enum, str):
    """Enumeration for resource types in the catalog."""
    RULE = 'rule'
    DECODER = 'decoder'
    INTEGRATION = 'integration'

class ResourceFormat(Enum, str):
    """Enumeration for resource formats in the catalog."""
    JSON = 'json'
    YAML = 'yaml'
    YML = 'yml'


class CatalogModule(BaseModule):
    """Module to interact with the Engine catalog resources."""

    async def create_resource(self, type: ResourceType, format: ResourceFormat, content: str, namespace_id: str) -> dict:
        """Create a new resource in the catalog.

        Parameters
        ----------
        type : ResourceType
            The type of the resource to create.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The content of the resource.
        namespace_id : str
            The namespace identifier.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {
            'type': type,
            'format': format,
            'content': content,
            'namespaceid': namespace_id
        }
        return await self.send('/catalog/resource/post', body)

    async def get_resource(self, name: str, format: ResourceFormat, namespace_id: str):
        """Retrieve a resource from the catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource.
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
            'namespaceid': namespace_id
        }
        return await self.send('/catalog/resource/get', body)

    async def update_resource(self, name: str, format: ResourceFormat, content: str, namespace_id: str):
        """Update an existing resource in the catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The new content of the resource.
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
        return await self.send('/catalog/resource/put', body)

    async def delete_resource(self, name: str, namespace_id: str):
        """Delete a resource from the catalog.

        Parameters
        ----------
        name : str
            The name of the resource to delete.
        namespace_id : str
            The namespace identifier.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {
            'name': name,
            'namespaceid': namespace_id
        }
        return await self.send('/catalog/resource/delete', body)

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
        return await self.send('/catalog/resource/validate', body)
