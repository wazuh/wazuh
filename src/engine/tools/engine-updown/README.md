# Engine updown

A Python tool to manage instances of the Engine

## Installation

You can install `engie-updown` via pip:

```bash
pip install ./engine-updown
```

## Usage
Simply import the engine handler and make an instance:
```py
from engine_updown.handler import EngineHandler

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
