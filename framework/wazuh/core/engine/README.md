## Engine API client

This folder contains the client class used to communicate with the Engine API client which uses HTTP and is exposed over unix sockets.

### Parameters

The client class has 3 parameters: `socket_path`, `retries` and `timeout`. Here are their default values:

- Socket path: `/var/ossec/queue/sockets/engine-api'`
- Retries: 5 seconds
- Timeout between retries: 1 second

This is, by default, the client will try to connect to the API a maximum of 5 times waiting 1 second between tries.

These values can be tweaked during the class creation. For example:

```py
from wazuh.core.engine import Engine

engine = Engine(socket_path='/var/ossec/queue/sockets/engine-api'', retries=10, timeout=3)
```

### Modular design

The client is designed to provide a seamless way of executing HTTP requests against the engine while making it easy to maintain and extend.

The class will have different modules which will be exposed to the client to perform different operations.

All modules inherit from the `BaseModule` and have access to the underlying client which holds the connection to the socket. Using the client is pretty straightforward:

```py
from wazuh.core.engine import Engine

engine = Engine()
response = await engine._client.get('http://docker/info')
```

Right now, there are no modules because the engine is still under heavy development, but let's use `Catalog` as an example. The code would look like

```py
class Engine:
    """Wazuh Engine API client."""

    def __init__(
        self,
        socket_path: str = ENGINE_API_SOCKET_PATH,
        retries: int = DEFAULT_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        transport = AsyncHTTPTransport(uds=socket_path, retries=retries)
        self._client = AsyncClient(transport=transport, timeout=Timeout(timeout))

        self.catalog = CatalogModule(client=self._client)

class CatalogModule(BaseModule):
    """Class to interact with Engine catalog module."""

    def __init__(self, client: AsyncClient) -> None:
        self._client = client
    
    async def get_resources(self) -> dict:
        return await self._client.post(
            url='http://localhost/catalog/resource/get',
            data={'name': 'decoder', 'format': 'yaml', 'namespaceid': 'system'}
        )
```

And using it would be simple as

```py
from wazuh.core.engine import Engine

engine = Engine()
response = await engine.catalog.get_resources()
```
