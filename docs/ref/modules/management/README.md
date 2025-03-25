# Management REST API

## Introduction

The REST API allows the remote management of the Wazuh infrastructure such as:
 - CRUD operations for agents
 - CRUD operations for groups
 - Agent's assignments to groups
 - CRUD operations for security entities (Users, Roles, Rules and Policies)
 - Restarting the node(s) or agent(s)

 ## Configuration

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| host | The host address for the communications API |  | 0.0.0.0 |
| post | The port number for the communications API |  | 55000 |
| drop_privileges | Whether to drop privileges after starting the API | | true |
| max_upload_size | The maximum upload size in bytes | | 10485760 |
| jwt_expiration_timeout | The expiration timeout for JWT in seconds | | 900 |

### Intervals

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| request_timeout | The timeout for requests in seconds |  | 10 |

### SSL

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| key | The path to the SSL key file | Yes |  |
| cert | The path to the SSL certificate file | Yes |  |
| use_ca | Whether to use a CA certificate |  | False |
| ca | The path to the CA certificate file |  | " " |
| ssl_protocol | The SSL protocol to use. Accepted values: TLS, TLSv1, TLSv1.1, TLSv1.2, auto |  | auto |
| ssl_ciphers | The SSL ciphers to use |  | " " |

### Logging

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| level | The logging level. Accepted values: debug, info, warning, error, critical |  | debug |
| format | The format for logging output. Accepted value: plain |  | plain |

### CORS

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| enabled | Whether CORS is enabled |  | false |
| source_route | The source route for CORS requests |  | "*" |
| expose_headers | Headers that are exposed to the client | | "*" |
| allow_headers | Headers that are allowed in requests | | "*" |
| allow_credentials | Whether to allow credentials in CORS requests | | False |

### Access

| Option | Description | Mandatory | Default |
|--------|-------------|-----------|---------|
| max_login_attempts | The maximum number of failed login attempts allowed | | 50 |
| block_time | The duration in seconds to block an IP after reaching the maximum login attempts | | 300 |
| max_request_per_minute | The maximum number of requests allowed per minute | | 300 |

```yaml
management_api:
  host:
    - 0.0.0.0
    - ::1
  port: 55000
  intervals:
    request_timeout: 10
  ssl:
    key: /etc/wazuh-server/certs/server-1-key.pem
    cert: /etc/wazuh-server/certs/server-1.pem
    use_ca: false
    ca: /etc/wazuh-server/certs/root-ca.pem
  logging:
    level: info
    format: plain
  cors:
    enabled: false
    source_route: *
    expose_headers: *
    allow_headers: *
    allow_credentials: false
  access:
    max_login_attempts: 50
    block_time: 300
    max_request_per_minute: 300
```