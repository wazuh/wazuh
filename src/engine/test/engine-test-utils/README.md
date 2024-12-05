# Engine updown

A Python library with utils for other testing scripts

## Installation

You can install `engine-test-utils` via pip:

```bash
pip install ./engine-test-utils
```

## Engine updown
### Usage
Simply import the engine handler and make an instance, then start the engine, do something with it and stop it.

```py
from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
            "path/to/engine", "path/to/configuration.env")

# Start the Engine
engine_handler.start()

# Do somenthing with the Engine, the api is available through the handler
request = {}
error, response = engine_handler.api_client.send_recv(request)

# Stop the Engine
engine_handler.stop()
```

The configuration file is a `.env` file with the following format:
```env
ENVIROMENT_VARIABLE=value
```

You can check the possible enviroment variables in `source/conf/src/conf.cpp` in `Conf::Conf` constructor.
