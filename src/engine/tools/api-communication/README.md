# API communication

The library provides a client interface to communicate locally with the engine (`wazuh-manager-analysisd`)
over its HTTP API Unix socket. It is the transport used by the `engine-suite`, `engine-metrics` and
`engine-test-utils` tools.

1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)

# Directory structure

```plaintext
api-communication/
├── pyproject.toml
└── src/
    └── api_communication/
        ├── __init__.py
        ├── client.py        # APIClient: send(), jsend(), send_recv()
        ├── endpoints.py     # get_endpoint(): request message -> (error, endpoint, HTTP method)
        └── proto/           # Generated Python protobuf modules (*_pb2.py, *_pb2.pyi)
```

The `proto/` modules are generated from the engine's `.proto` files in `src/engine/source/proto/src/`.

# Install

From `src/engine/`:

```bash
pip3 install tools/api-communication/
```

It requires Python 3.8 or newer and installs `protobuf` and `httpx` (`pyproject.toml`).

# Usage

`APIClient(api_socket)` takes the path of the engine API socket; on an installed manager it is
`/var/wazuh-manager/queue/sockets/engine-api-http.sock`. The endpoint and HTTP method are deduced from the
type of the request message (`endpoints.py`); an unknown message type is returned as an error.

- `send(request, response_type)` serializes a protobuf request message.
- `jsend(json_body, request_type, response_type)` sends an already built dictionary.

Both return a tuple `(error, response)`: `error` is `None` on success, and otherwise a string (a transport
error, an unparsable response, or the `error` field of a response whose `status` is not `OK`), with an empty
dictionary as `response`.

For example, to get a resource from a namespace:

```python
import json
import sys

from api_communication.client import APIClient
from api_communication.proto.crud_pb2 import resourceGet_Request, resourceGet_Response

client = APIClient('/var/wazuh-manager/queue/sockets/engine-api-http.sock')

request = resourceGet_Request()
request.space = 'standard'
request.uuid = '<resource-uuid>'

error, response = client.send(request, resourceGet_Response())
if error:
    sys.exit(f'Error getting the resource: {error}')

print(json.dumps(response['jsonContent'], indent=4))
```
