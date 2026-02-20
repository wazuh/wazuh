# Testing

The Server API and Framework use `pytest` as the test runner. Tests are organized alongside each module.

---

## Test Locations

| Location | Scope |
|----------|-------|
| `framework/wazuh/tests/` | Interface layer unit tests |
| `framework/wazuh/core/tests/` | Core logic unit tests |
| `api/api/test/` | API layer unit tests |
| `api/api/controllers/test/` | Controller tests |
| `framework/wazuh/rbac/tests/` | RBAC unit tests |
| `framework/wazuh/core/indexer/tests/` | Indexer integration tests |

---

## Running Tests

```bash
export WAZUH_REPO=<your_path>
PYTHONPATH=$WAZUH_REPO/framework:$WAZUH_REPO/api pytest framework --disable-warnings
```

### Running specific test modules

```bash
# Interface layer tests
PYTHONPATH=$WAZUH_REPO/framework:$WAZUH_REPO/api pytest framework/wazuh/tests/ --disable-warnings

# Core logic tests
PYTHONPATH=$WAZUH_REPO/framework:$WAZUH_REPO/api pytest framework/wazuh/core/tests/ --disable-warnings

# API layer tests
PYTHONPATH=$WAZUH_REPO/framework:$WAZUH_REPO/api pytest api/api/test/ --disable-warnings
```

---

## Configuration

The project uses `pytest.ini` files for test configuration. These are located at:
- `framework/pytest.ini`
- `api/api/pytest.ini`
