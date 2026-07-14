# Server API Configuration Reference

Complete configuration reference for the Server API and Framework module.

The Server API provides a RESTful interface for Wazuh manager operations, including agent management, cluster coordination, and security controls. Configuration is managed through YAML files, not the traditional XML configuration.

- **Module:** Manager-only
- **Configuration format:** YAML
- **Security:** JWT authentication, RBAC authorization, TLS/SSL support

For module overview and architecture, see [Server API Module](index.html).

---

## Configuration

**Configuration file:** `/var/wazuh-manager/api/configuration/api.yaml`

**XML Section:** None (YAML-based configuration)

**Internal Options:** None

The API configuration is stored in YAML format and validated against JSON schemas at startup.

### API Configuration File

The main API configuration file defines:

- Host binding and port settings
- HTTPS/TLS configuration
- CORS settings
- Upload limits and timeouts
- Authentication pool sizing
- Request timeout intervals
- Logging configuration

**Configuration directory structure:**

| Path | Description |
|------|-------------|
| `api/configuration/api.yaml` | Main API configuration |
| `api/configuration/security/` | Security configuration directory |

### authentication_pool_size

Size of the authentication thread pool for handling concurrent login requests.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `50`
- **Note:** Increase for high-concurrency environments with many simultaneous login attempts

### intervals

API timing and timeout configuration.

#### request_timeout

Maximum time in seconds for API request processing.

- **Default value:** `10`
- **Allowed values:** Non-negative number (seconds, decimals allowed)
- **Note:** Requests exceeding this timeout are terminated

### Security Configuration

Security settings control authentication and authorization behavior.

**File location:** `api/configuration/security/`

**Validation:** JSON Schema validated at startup

#### auth_token_exp_timeout

JWT token expiration time in seconds.

- **Default value:** `900` (15 minutes)
- **Allowed values:** Positive integer
- **Note:** Shorter timeouts increase security but require more frequent re-authentication

#### rbac_mode

Role-Based Access Control enforcement mode.

- **Default value:** `white`
- **Allowed values:**
  - `white` - Deny by default (recommended)
  - `black` - Allow by default
- **Note:** White-list mode provides better security by requiring explicit permission grants

---

## Configuration Examples

### Default API Configuration

Standard API settings for most deployments:

```yaml
host: 0.0.0.0
port: 55000
drop_privileges: true
max_upload_size: 10485760  # 10 MB
authentication_pool_size: 2
intervals:
  request_timeout: 10
cors:
  enabled: false
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: false
access:
  max_login_attempts: 5
  block_time: 300
  max_request_per_minute: 300
upload_configuration:
  agents:
    allow_higher_versions:
      allow: true
  indexer:
    allow: true
logs:
  level: info
```

### Secure Production Configuration

Enhanced security settings for production environments:

```yaml
host: 0.0.0.0
port: 55000
drop_privileges: true
max_upload_size: 10485760
authentication_pool_size: 2
intervals:
  request_timeout: 10
cors:
  enabled: false
access:
  max_login_attempts: 3
  block_time: 900  # 15 minutes
  max_request_per_minute: 100
upload_configuration:
  agents:
    allow_higher_versions:
      allow: true
  indexer:
    allow: true
logs:
  level: warning
https:
  enabled: true
  key: /var/wazuh-manager/etc/certs/api-key.pem
  cert: /var/wazuh-manager/etc/certs/api-cert.pem
  use_ca: true
  ca: /var/wazuh-manager/etc/certs/root-ca.pem
```

### Development Configuration

Relaxed settings for development and testing:

```yaml
host: 0.0.0.0
port: 55000
drop_privileges: false
max_upload_size: 52428800  # 50 MB
authentication_pool_size: 4  # Higher for dev testing
intervals:
  request_timeout: 30  # Longer for debugging
cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: true
access:
  max_login_attempts: 10
  block_time: 60
  max_request_per_minute: 1000
logs:
  level: debug
```

### Custom JWT Configuration

Adjust token expiration and RBAC mode:

```yaml
# In security configuration
auth_token_exp_timeout: 1800  # 30 minutes
rbac_mode: white
```

---

## Framework Configuration

The API framework reads additional configuration from the manager configuration file.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

The framework parses manager configuration for:
- Component-specific settings
- Integration parameters
- Global limits and thresholds

Configuration parsing uses `lxml` and `defusedxml` for XML validation.

---

## Global Constants and Context

Runtime constants and limits are defined in `core/common.py`.

### Important Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SOCKET_BUFFER_SIZE` | 64 KB | Maximum socket buffer |
| `MAX_GROUPS_PER_MULTIGROUP` | 128 | Maximum groups per multigroup |
| `AGENT_NAME_LEN_LIMIT` | 128 | Maximum agent name length |
| `DATABASE_LIMIT` | 500 | Default query result limit |
| `MAXIMUM_DATABASE_LIMIT` | 100,000 | Hard cap on query results |

### Path Discovery

The framework automatically discovers the Wazuh installation root using `find_wazuh_path()` and retrieves system user/group IDs via `wazuh_uid()` and `wazuh_gid()`.

### Context Variables

Request-scoped state is managed using Python `contextvars`:

| Variable | Description |
|----------|-------------|
| `rbac_mode` | Current RBAC mode (`white` or `black`) |
| `current_user` | Authenticated user for the current request |
| `cluster_nodes` | Available cluster nodes |
| `origin_module` | Calling module context |

Use `reset_context_cache()` decorator for request-scoped caching.

---

## Performance Considerations

### Request Rate Limiting

Control API load using `max_request_per_minute`:

**Small deployments (<10 users):**
```yaml
max_request_per_minute: 300
```

**Medium deployments (10-50 users):**
```yaml
max_request_per_minute: 600
```

**Large deployments (50+ users):**
```yaml
max_request_per_minute: 1000
```

### Response Caching

Enable caching to reduce repeated query overhead:

```yaml
cache:
  enabled: true
  time: 0.750  # 750ms cache lifetime
```

**Recommendations:**
- Enable for production environments
- Disable for development to see immediate changes
- Adjust cache time based on update frequency

### Database Query Limits

Use pagination for large result sets:

- Default limit: 500 results
- Maximum limit: 100,000 results
- Use `offset` and `limit` parameters in API calls

---

## Monitoring

### Check API Status

Verify API is running and responsive:

```bash
curl -k -X GET "https://localhost:55000/" \
  -H "Content-Type: application/json"
```

### View API Logs

Monitor API activity and errors:

```bash
# API logs
tail -f /var/wazuh-manager/logs/api.log

# API access logs
tail -f /var/wazuh-manager/logs/api/access.log

# API error logs
tail -f /var/wazuh-manager/logs/api/error.log
```

### Authentication Monitoring

Track failed login attempts:

```bash
grep "authentication failed" /var/wazuh-manager/logs/api.log
```

### Performance Metrics

Check API response times and request rates:

```bash
# Request rate
grep "GET\|POST\|PUT\|DELETE" /var/wazuh-manager/logs/api/access.log | \
  wc -l

# Slow requests (>1s)
grep -E "time=[0-9]{4,}" /var/wazuh-manager/logs/api/access.log
```

---

## Troubleshooting

### API Won't Start

**Check configuration syntax:**
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('/var/wazuh-manager/api/configuration/api.yaml'))"
```

**Verify permissions:**
```bash
ls -l /var/wazuh-manager/api/configuration/api.yaml
# Should be owned by wazuh-manager:wazuh-manager
```

### Authentication Failures

**Check token expiration:**
```bash
# Review security configuration
cat /var/wazuh-manager/api/configuration/security/security.yaml
```

**Verify user exists:**
```bash
# List API users
/var/wazuh-manager/bin/wazuh-apid -l
```

### High Memory Usage

**Disable caching or reduce cache time:**
```yaml
cache:
  enabled: false
  # Or reduce cache time
  time: 0.250
```

**Reduce concurrent requests:**
```yaml
access:
  max_request_per_minute: 100
```

### CORS Issues

**Enable CORS for development:**
```yaml
cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: true
```

**Note:** Restrict CORS in production to specific origins.

---

## See Also

- [Server API Module](index.html) - Module overview and architecture
- [API Reference](api-reference.html) - Complete API endpoint documentation
- [RBAC Configuration](../rbac/configuration.html) - Role-based access control
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
