# API communication

The library provides a client interface to communicate locally with wazuh-engine. 


1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)

# Directory structure

```bash
├── api-communication/
|   └── src
|     └── api-communication
|           └── proto
|               └── __init__.py
|               └── components_pb2.py
|               └── components_pb2.pyi
|           └── __init_.py
|           └── client.py
|           └── command.py
|     └── README.md
|     └── setup.cfg
|     └── setup.py
```

# Install

To install the library, run the following command:

```bash
`pip3 install tools/api-communication/`
```


# Usage

The library provides a client interface to communicate with wazuh-engine.

For example, to get a resource from the engine, you can use the following code:

```python
# Import the APIClient class
from api_communication.client import APIClient 
# Import the proto file, with the request and response messages
from api_communication.proto.catalog_pb2 import ResourceGet_Request, ResourceGet_Response

client = APIClient()
client.connect()

    # Create the json request 
    json_request = dict()
    json_request['namespaceid'] = args['namespace']
    json_request['name'] = args['asset']
    json_request['format'] = args['format']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, ResourceGet_Request(), ResourceGet_Response())

        if error:
            sys.exit(f'Error getting asset or collection: {error}')

        print(response['content'])

    except Exception as e:
        sys.exit(f'Error getting asset or collection: {e}')

    return 0
```
