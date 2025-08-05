## Engine API client

This folder contains the client class used to communicate with the Engine API client which uses HTTP and is exposed over unix sockets.

### Parameters

The client class has 3 parameters: `socket_path`, `retries` and `timeout`. Here are their default values:

- Socket path: `/var/ossec/queue/sockets/engine-api'`
- Retries: 5
- Timeout: 5 seconds

This is, by default, the client will try to connect to the API a maximum of 5 times waiting 5 seconds between tries.

These values can be tweaked during the class creation. For example:

```py
from wazuh.core.engine import Engine

engine = Engine(socket_path='/var/ossec/queue/sockets/engine-api', retries=10, timeout=3)
```

### Client

The client is designed to provide a seamless way of executing HTTP requests against the engine while making it easy to maintain and extend.

```py
from wazuh.core.engine import get_engine_client

async with get_engine_client() as engine:
    response = await engine._client.get('http://localhost/info')
```

The class will have different modules which will be exposed to the client to perform different operations.

However, it's better to use the `send` method from modules that inherit from `BaseModule`.

### Modular design

The `BaseModule` class provides the foundation for all engine modules. It includes:

- Access to the HTTP client via `self._client`
- A logger instance via `self._logger`
- The `send` method for making HTTP requests with proper error handling

The `send` method automatically:
- Normalizes paths (adds leading slash if missing)
- Handles common HTTP exceptions and converts them to `WazuhEngineError`
- Parses JSON responses
- Uses appropriate timeouts for local Unix socket connections

Right now, there are no modules because the engine is still under heavy development, but let's use `Catalog` as an example. The code would look like

```py
class Engine:
    """Wazuh Engine API client."""

    def __init__(self, ...) -> None:
        ...

        # Register the module
        self.catalog = CatalogModule(client=self._client)

class CatalogModule(BaseModule):
    """Class to interact with Engine catalog module."""

    MODULE = 'catalog'
    
    async def get_resources(self) -> dict:
        return await self.send(
            path='/catalog/resource/get',
            data={'name': 'decoder', 'format': 'yaml', 'namespaceid': 'system'}
        )
```

And using it would be simple as

```py
from wazuh.core.engine import get_engine_client

async with get_engine_client() as engine:
    response = await engine.catalog.get_resources()
```
