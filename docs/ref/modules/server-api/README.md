# Server API

The **Server API** is the REST interface used to manage and interact with the Wazuh manager. It is backed by a **Python Framework** that implements all business logic, RBAC enforcement, and communication with internal daemons.

The API exposes endpoints for agent management, security configuration, cluster operations, file integrity monitoring, and more. All requests are authenticated via **JWT tokens** and authorized through a **Role-Based Access Control (RBAC)** system.

## Key Features

- **REST API**: Full management interface over HTTPS
- **JWT Authentication**: Short-lived EC-signed tokens
- **RBAC**: Fine-grained permission control per endpoint and resource
- **Distributed API (DAPI)**: Transparent request routing across cluster nodes
- **WQL**: Server-side query language for filtering large datasets
- **OpenAPI 3.0**: Fully specified API contract (`spec/spec.yaml`)

## Key Concepts

| Concept | Description |
|---------|-------------|
| Server API | REST API used to manage agents, manager, cluster, and security |
| Framework | Python backend implementing API behavior and business logic |
| Core Layer | Low-level logic and system interactions |
| RBAC | Role-Based Access Control enforced per endpoint |
| JWT | Authentication mechanism for all API calls |
| WQL | Query language for filtering and searching API data |
| DAPI | Distributed API layer for cluster-aware request routing |

## Components

- [Architecture](architecture.md) — System architecture, directory structure, execution flow, and DAPI
- [Authentication & Security](authentication.md) — JWT, RBAC, rate limiting, and security headers
- [API Reference](api-reference.md) — Endpoints, WQL, error handling, and input validation
- [Configuration](configuration.md) — API, security, and manager configuration
- [Testing](testing.md) — Test structure, locations, and how to run tests

## Technology Stack

| Component | Technology |
|-----------|------------|
| Web Framework | Starlette + Connexion |
| API Specification | OpenAPI 3.0 (`spec.yaml`) |
| Authentication | PyJWT with EC keys |
| Async HTTP | aiohttp (for WDB HTTP client) |
| Database | Wazuh DB (SQLite via Unix sockets) |
| Security Headers | secure (Python library) |
| File Watching | asyncio + inotify |
| XML Parsing | lxml + defusedxml |
| Testing | pytest |

## Related Modules

- **wazuh-db**: Stores agent, group, and security data queried by the framework
- **analysisd**: Receives events ingested through the `/events` endpoint
- **authd**: Handles agent registration triggered via `/agents` endpoints
- **remoted**: Agent communication managed through the API
- **Wazuh Dashboard**: Consumes the same Server API for its UI
