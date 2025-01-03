import asyncio

import httpx

from wazuh.core import common
from wazuh.core.wlogging import WazuhLogger
from wazuh.core.engine.base import APPLICATION_JSON


async def get_orders(logger: WazuhLogger):
        """Get orders from the indexer and send to the Communications API unix socket HTTP server."""


        transport = httpx.AsyncHTTPTransport(uds=common.COMMS_API_SOCKET_PATH)
        client = httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(10))

        while True:
            logger.info('Getting orders from indexer')
            #TODO: Get the orders from the indexer
            commands = {'commands': []}

            try:
                response = await client.post(
                    url='http://localhost/api/v1/commands',
                    json=commands,
                    headers={
                        'Accept': APPLICATION_JSON,
                        'Content-Type': APPLICATION_JSON,
                    }
                )

                logger.debug(f'Post orders response: {response}')

                if response.status_code != 200:
                    logger.error(f'Post orders failed: {response.status_code} - {response.json()}')

                await asyncio.sleep(10)
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                logger.error(f'An error occurs sending the orders to the Communications API :', str(e))
