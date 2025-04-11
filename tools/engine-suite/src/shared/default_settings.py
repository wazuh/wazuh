from enum import Enum

class Constants:
    SOCKET_PATH: str = '/run/wazuh-server/engine-api.socket'
    DEFAULT_POLICY: str = 'policy/wazuh/0'
    DEFAULT_NS: str = 'user'
    INDEX_PATTERN: str = 'wazuh-alerts-5.x-0001'
    DEFAULT_API_TIMEOUT: int = 1000000

class CONFIG_ENV_KEYS(Enum):
    API_SERVER_SOCKET: str = 'WAZUH_SERVER_API_SOCKET'
    API_TIMEOUT: str = 'WAZUH_SERVER_API_TIMEOUT'
    LOG_LEVEL: str = 'WAZUH_LOG_LEVEL'
