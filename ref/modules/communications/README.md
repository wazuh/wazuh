# Communications REST API

## Introduction

The REST API is responsible for managing the agent's communications with the server.
It allows:
  - Receiving different event types, such as stateless and stateful.
  - Retrieving files and commands available for an agent.
  - Acting as an intermediary toward the engine, for example executing a VD scan on demand.

## Configuration

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| host | The host address for the communications API |  | 0.0.0.0 |
| post | The port number for the communications API |  | 27000 |
| workers | The number of worker threads for the communications API |  | 4 |

### Logging

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| level | The logging level. Accepted values: debug, info, warning, error, critical |  | debug |
| format | The format for logging output. Accepted value: plain |  | plain |

### Batcher

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| max_elements | The maximum number of elements in the batch |  | 5 |
| max_size | The maximum size in bytes of the batch |  | 3000 |
| wait_time | The time in seconds to wait before sending the batch |  | 0.15 |

### SSL

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| key | The path to the SSL key file | Yes |  |
| cert | The path to the SSL certificate file | Yes |  |
| use_ca | Whether to use a CA certificate |  | False |
| ca | The path to the CA certificate file |  | " " |
| ssl_protocol | The SSL protocol to use. Accepted values: TLS, TLSv1, TLSv1.1, TLSv1.2, auto |  | auto |
| ssl_ciphers | The SSL ciphers to use |  | " " |


```yaml
communications_api:
  host: 0.0.0.0
  port: 27000
  workers: 4
  logging:
    level: info
    format: plain
  batcher:
    max_elements: 5
    max_size: 3000
    wait_time: 0.15
  ssl:
    key: /etc/wazuh-server/certs/server-1-key.pem
    cert: /etc/wazuh-server/certs/server-1.pem
    use_ca: false
    ca: /etc/wazuh-server/certs/root-ca.pem
```