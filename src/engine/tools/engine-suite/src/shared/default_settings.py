from enum import Enum

class Constants:
    """
    A collection of constants used throughout the Wazuh Engine API integration.

    Attributes:
        SOCKET_PATH (str): Path to the Unix socket used to communicate with the engine API.
        DEFAULT_POLICY (str): Default policy path used when none is explicitly provided.
        DEFAULT_SESSION (str): Default session name.
        DEFAULT_NS (str): Default namespace under which requests are made.
        INDEX_PATTERN (str): Default OpenSearch index pattern where Wazuh alerts are stored.
        DEFAULT_API_TIMEOUT (int): Default timeout (in microseconds) configured on the server
                                   for API requests.
    """
    SOCKET_PATH: str = '/var/ossec/queue/sockets/engine-api'
    DEFAULT_POLICY: str = 'policy/wazuh/0'
    DEFAULT_SESSION: str = 'default'
    DEFAULT_NS: str = 'user'
    INDEX_PATTERN: str = 'wazuh-alerts-5.x-0001'
    DEFAULT_API_TIMEOUT: int = 1000000

class CONFIG_ENV_KEYS(Enum):
    API_SERVER_SOCKET: str = 'WAZUH_SERVER_API_SOCKET'
    API_TIMEOUT: str = 'WAZUH_SERVER_API_TIMEOUT'
    LOG_LEVEL: str = 'WAZUH_LOG_LEVEL'
