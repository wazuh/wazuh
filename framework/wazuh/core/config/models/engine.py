from pydantic import FilePath, PositiveInt, PositiveFloat

from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.logging import LoggingConfig


# TODO(#25121): Change the socket path once the Cpp team does it
DEFAULT_ENGINE_SOCKET_PATH = "/var/wazuh/queue/engine.sock"


class EngineClientConfig(WazuhConfigBaseModel):
    """Configuration for the Engine client.

    Parameters
    ----------
    api_socket_path : FilePath
        The path to the API socket. Default: "/var/wazuh/queue/engine.sock".
    retries : PositiveInt
        The number of retry attempts. Default: 3.
    timeout : PositiveFloat
        The timeout duration in seconds. Default: 10.0.
    """
    api_socket_path: FilePath = FilePath(DEFAULT_ENGINE_SOCKET_PATH)
    retries: PositiveInt = 3
    timeout: PositiveFloat = 10


class EngineConfig(WazuhConfigBaseModel):
    """Configuration for the Engine.

    Parameters
    ----------
    tzdv_automatic_update : bool
        Whether to enable automatic updates for TZDV. Default: False.
    client : EngineClientConfig
        Configuration for the Engine client. Default is an instance of EngineClientConfig.
    logging : LoggingConfig
        Configuration for logging. Default is an instance of LoggingConfig.
    """
    tzdv_automatic_update: bool = False
    client: EngineClientConfig() = EngineClientConfig()
    logging: LoggingConfig = LoggingConfig()
