from wazuh.core.engine.base import BaseModule

class LogModule(BaseModule):
    """Module to interact with the Engine's log endpoints."""

    MODULE = 'log'

    async def log_test(self, payload: str):
        """Send a test log payload to the engine.

        Parameters
        ----------
        payload : str
            The log payload to send.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        body = {'payload': payload}
        return await self.send('/v1/log/test', body)
