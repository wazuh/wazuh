# API communication

1. [Directory structure](#directory-structure)
1. [Install](#install)

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
This package does not expose entry points since it only serves as support for the other packages that need to communicate through a unix socket to send and receive data

`pip3 install tools/api-communication/`
