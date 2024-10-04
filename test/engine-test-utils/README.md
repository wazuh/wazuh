# Engine updown

A Python library with utils for other testing scripts

## Installation

You can install `engine-test-utils` via pip:

```bash
pip install ./engine-test-utils
```

## Engine updown
### Usage
Simply import the engine handler and make an instance:
```py
from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
            "path/to/engine", "path/to/configuration.conf")

# Start the Engine
engine_handler.start()

# Do somenthing with the Engine, the api is available through the handler
request = {}
error, response = engine_handler.api_client.send_recv(request)

# Stop the Engine
engine_handler.stop()
```
