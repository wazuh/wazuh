# Server API

The **Server API** is the REST interface used to manage and interact with the Wazuh manager. It is backed by a **Python Framework** that implements all business logic, RBAC enforcement, and communication with internal daemons.

The API exposes endpoints for agent and group management, enrollment tokens, cluster operations and node configuration, security (users, roles, policies, rules), and the MITRE ATT&CK database. Every request except the two login endpoints is authenticated with a **JWT token** and authorized through a **Role-Based Access Control (RBAC)** system.

The API is served by `wazuh-manager-apid`, on port `55000` by default, and **only on the master node**: `wazuh-manager-control` skips `wazuh-manager-apid` on a worker, so a cluster has a single API endpoint, and requests that concern a worker reach it through the [Distributed API](architecture.md#distributed-api-dapi).

## Key Features

- **REST API**: Full management interface over HTTPS
- **JWT Authentication**: Short-lived tokens signed with ES512 (900 seconds by default)
- **RBAC**: Fine-grained permission control per endpoint and resource, including a separate action for reading the configuration secrets in clear (see [Authentication](authentication.md#sensitive-configuration-values))
- **Distributed API (DAPI)**: Transparent request routing across cluster nodes
- **`q` query filter**: Server-side query language for filtering large datasets
- **OpenAPI 3.0**: Fully specified API contract (`api/api/spec/spec.yaml`)

## Key Concepts

| Concept | Description |
|---------|-------------|
| Server API | REST API used to manage agents, groups, cluster nodes, and security |
| Framework | Python backend implementing API behavior and business logic |
| Core Layer | Low-level logic and system interactions |
| RBAC | Role-Based Access Control enforced per endpoint |
| JWT | Authentication mechanism for all API calls |
| `q` query filter | Filter syntax for searching API data |
| DAPI | Distributed API layer for cluster-aware request routing |

## Components

- [Architecture](architecture.md) — System architecture, directory structure, execution flow, and DAPI
- [Authentication & Security](authentication.md) — JWT, RBAC, rate limiting, and security headers
- [API Reference](api-reference.md) — Endpoints, `q` query filter syntax, error handling, and input validation
- [Configuration](configuration.md) — API, security, and manager configuration
- [Testing](testing.md) — Test structure, locations, and how to run tests

## Technology Stack

| Component | Technology |
|-----------|------------|
| Web Framework | Starlette + Connexion, served by uvicorn |
| API Specification | OpenAPI 3.0 (`spec.yaml`) |
| Authentication | PyJWT with EC keys |
| HTTP clients to the daemons | httpx (Unix-socket HTTP APIs of wazuh-manager-db, analysisd, remoted, task manager, vulnerability scanner) |
| Databases | Wazuh DB (through its Unix sockets); `rbac.db` (SQLite, through SQLAlchemy) |
| Security Headers | secure (Python library) |
| File Watching | asyncinotify (JWT key rotation) |
| XML Parsing | defusedxml |
| Testing | pytest |

## Related Modules

- **wazuh-manager-db**: Stores the agent and group data queried by the framework
- **wazuh-manager-authd**: Handles the agent registrations, deletions and enrollment tokens requested through the `/agents` endpoints
- **wazuh-manager-remoted**: Reports its statistics and TLS listener state to the `/cluster/{node_id}/daemons/*` endpoints
- **[RBAC](../rbac/README.md)**: The authorization model the API enforces
- **Wazuh Dashboard**: Consumes the same Server API for its UI, as the `wazuh-internal-client` user
