import pytest

from wazuh.core.config.models.central_config import Config, EngineConfig, ManagementAPIConfig, CommsAPIConfig


@pytest.mark.parametrize("init_values, expected", [
    ({
        "indexer": {"host": "localhost", "port": 9200, "user": "user_example", "password": "password_example"},
        "server": {"nodes": ["master"], "node": {"name": "example", "type": "master", "ssl":
            {"key": "value", "cert": "value", "ca": "value"}}}
     },
     {
        "node": {"name": "example", "type": "master", "ssl": {"key": "value", "cert": "value", "ca": "value"}},
        "server": {"nodes": ["master"], "port": 1516, "bind_addr": "localhost", "hidden": False, "update_check": False,
                   "logging.level": "debug2"},
        "indexer": {"host": "localhost", "port": 9200, "user": "user_example", "password": "password_example"},
        "engine": {},
        "management_api": {},
        "communications_api": {}
    }),
])
def test_config_default_values(init_values, expected):
    """Check the correct initialization of the `Config` class."""
    config = Config(**init_values)

    assert config.server.port == expected["server"]["port"]
    assert config.server.bind_addr == expected["server"]["bind_addr"]
    assert config.server.hidden == expected["server"]["hidden"]
    assert config.server.update_check == expected["server"]["update_check"]
    assert config.server.logging.level == expected["server"]["logging.level"]

    assert config.engine == EngineConfig(**expected["engine"])
    assert config.management_api == ManagementAPIConfig(**expected["management_api"])
    assert config.communications_api == CommsAPIConfig(**expected["communications_api"])
