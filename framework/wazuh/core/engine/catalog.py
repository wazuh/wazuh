from enum import Enum
from wazuh.core.engine.base import BaseModule


class ResourceType(str, Enum):
    """Enumeration of possible resource types for the Engine catalog.

    Values
    ------
    DECODER : str
        Decoder resource type.
    RULE : str
        Rule resource type.
    FILTER : str
        Filter resource type.
    OUTPUT : str
        Output resource type.
    INTEGRATION : str
        Integration resource type.
    """
    DECODER = "decoder"
    RULE = "rule"
    FILTER = "filter"
    OUTPUT = "output"
    INTEGRATION = "integration"

class ResourceFormat(str, Enum):
    """Enumeration of possible resource formats for the Engine catalog.

    Values
    ------
    JSON : str
        JSON format.
    YAML : str
        YAML format.
    YML : str
        YML format (alternative YAML extension).
    """
    JSON = "json"
    YAML = "yaml"
    YML = "yml"

class CatalogModule(BaseModule):
    """Class to interact with the Engine Catalog module."""

    MODULE = 'catalog'

    async def create_resource(self, type: ResourceType, format: ResourceFormat, content: str, namespece: str) -> dict:
        """Create a new resource in the Engine catalog.

        Parameters
        ----------
        type : ResourceType
            The type of the resource (e.g., decoder, rule).
        format : ResourceFormat
            The format of the resource content (e.g., json, yaml).
        content : str
            The content of the resource.
        namespece : str
            The namespace identifier for the resource.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path=f'/catalog/resource/post',
            data={
                'type': type,
                'format': format,
                'content': content,
                'namespaceid': namespece
            }
        )

    async def get_resource(self, name: str, format: ResourceFormat, namespace: str) -> dict:
        """Retrieve a resource from the Engine catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
        namespace : str
            The namespace identifier for the resource.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path=f'/catalog/resource/get',
            data={
                'name': name,
                'format': format,
                'namespaceid': namespace
            }
        )


    async def update_resource(self, name: str, format: ResourceFormat, content: str, namespace: str) -> dict:
        """Update an existing resource in the Engine catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The new content of the resource.
        namespace : str
            The namespace identifier for the resource.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path=f'/catalog/resource/put',
            data={
                'name': name,
                'format': format,
                'content': content,
                'namespaceid': namespace
            }
        )

    async def delete_resource(self, name: str, namespace: str) -> dict:
        """Delete a resource from the Engine catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        namespace : str
            The namespace identifier for the resource.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='f/catalog/resource/delete',
            data={
                'name': name,
                'namespaceid': namespace
            }
        )

    async def validate_resource(self, name: str, format: ResourceFormat, content: str, namespace: str) -> dict:
        """Validate a resource in the Engine catalog.

        Parameters
        ----------
        name : str
            The name of the resource.
        format : ResourceFormat
            The format of the resource content.
        content : str
            The content of the resource.
        namespace : str
            The namespace identifier for the resource.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path=f'/catalog/resource/validate',
            data={
                'name': name,
                'format': format,
                'content': content,
                'namespaceid': namespace
            }
        )
