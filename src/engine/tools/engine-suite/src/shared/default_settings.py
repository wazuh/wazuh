from enum import Enum

class Constants:
    """
    A collection of constants used throughout the Wazuh Engine API integration.

    Attributes:
        SOCKET_PATH (str): Path to the Unix socket used to communicate with the engine API.
        DEFAULT_NAMESPACE (str): Default namespace path used when none is explicitly provided.
        DEFAULT_SESSION (str): Default session name.
        DEFAULT_API_TIMEOUT (int): Default timeout (in microseconds) configured on the server
                                   for API requests.
    """
    SOCKET_PATH: str = '/var/wazuh-manager/queue/sockets/analysis'
    DEFAULT_NAMESPACE: str = 'testing'
    DEFAULT_SESSION: str = 'default'
    DEFAULT_NS: str = 'draft'
    DEFAULT_API_TIMEOUT: int = 1000000
    PLACEHOLDER = "ENV_PATH_PLACEHOLDER"

class CONFIG_ENV_KEYS(Enum):
    API_SERVER_SOCKET: str = 'WAZUH_MANAGER_API_SOCKET'
    API_TIMEOUT: str = 'WAZUH_MANAGER_API_TIMEOUT'
    LOG_LEVEL: str = 'WAZUH_STANDALONE_LOG_LEVEL'
