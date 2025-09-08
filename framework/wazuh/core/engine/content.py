from wazuh.core.engine.base import BaseModule

class ContentModule(BaseModule):
    """Module to interact with the Engine's content endpoints."""

    MODULE = 'content'

    async def get_content_status(self) -> dict:
        """Get the status of the content module.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.get('/v1/content/status')

    async def put_content_reload(self) -> dict:
        """Reload the content module.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.put('/v1/content/reload')

    async def put_content_validation(self, type: str, payload: str) -> dict:
        """Validate content of a specific type.

        Parameters
        ----------
        type : str
            The type of content to validate.
        payload : str
            The content payload to validate.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {'type': type, 'payload': payload}
        return await self.put('/v1/content/validation', body)

    async def delete_content(self, asset_name: str) -> dict:
        """Delete a specific content asset.

        Parameters
        ----------
        asset_name : str
            The name of the asset to delete.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        path = f'/v1/content/{asset_name}'
        return await self.delete(path)
