# Configuration

The Server API and Framework read configuration from multiple sources: YAML files for the API layer, `ossec.conf` for the manager, and internal constants for runtime limits.

---

## API Configuration

The API reads its configuration from files defined in `api/constants.py`:

| Path | Description |
|------|-------------|
| `api/configuration/api.yaml` | Main API configuration |
| `api/configuration/security/` | Security configuration directory |

### Security Configuration (JSON Schema validated)

| Setting | Description | Values |
|---------|-------------|--------|
| `auth_token_exp_timeout` | JWT token expiration time | Default: 900 seconds |
| `rbac_mode` | RBAC enforcement mode | `white` (deny by default) / `black` (allow by default) |

---

## Manager Configuration

- `ossec.conf` is parsed by `core/configuration.py`
- Configuration sections are validated per component
- XML validation uses `lxml` and `defusedxml`

---

## Global Constants & Context (`core/common.py`)

This module centralizes all Wazuh paths, limits, and runtime context.

### Key Functions

| Function | Description |
|----------|-------------|
| `find_wazuh_path()` | Auto-discovers the Wazuh installation root |
| `wazuh_uid()` / `wazuh_gid()` | Gets the wazuh-manager system user/group IDs |
| `get_installation_uid()` | Returns (or creates) a persistent UUID |
| `reset_context_cache()` | Decorator for request-scoped caching |

### Important Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SOCKET_BUFFER_SIZE` | 64 KB | Maximum socket buffer |
| `MAX_GROUPS_PER_MULTIGROUP` | 128 | Maximum groups per multigroup |
| `AGENT_NAME_LEN_LIMIT` | 128 | Maximum agent name length |
| `DATABASE_LIMIT` | 500 | Default query result limit |
| `MAXIMUM_DATABASE_LIMIT` | 100,000 | Hard cap on query results |

### Context Variables

Request-scoped state managed via `contextvars`:

| Variable | Description |
|----------|-------------|
| `rbac_mode` | Current RBAC mode (`white` or `black`) |
| `current_user` | Authenticated user for the current request |
| `cluster_nodes` | Available cluster nodes |
| `origin_module` | Calling module context |
