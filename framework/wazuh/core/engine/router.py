from wazuh.core.engine.base import BaseModule

class RouterModule(BaseModule):
    """Class to interact with the Engine Router module."""

    MODULE = 'Router'

    async def reload_route(self, name: str) -> dict:
        """Reload a route in the Engine router.

        Parameters
        ----------
        name : str
            The name of the route to reload.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/router/route/reload',
            data={
                'name': name
            }
        )
