from typing import Any, Dict

from pydantic import FilePath, PositiveFloat, PositiveInt, model_serializer
from wazuh.core.common import ENGINE_SOCKET
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.logging import EngineLoggingConfig


class EngineClientConfig(WazuhConfigBaseModel):
    """Configuration for the Engine client.

    Parameters
    ----------
    api_socket_path : FilePath
        The path to the API socket. Default: "/run/wazuh-server/engine.socket".
    retries : PositiveInt
        The number of retry attempts. Default: 3.
    timeout : PositiveFloat
        The timeout duration in seconds. Default: 10.0.
    """

    api_socket_path: FilePath = FilePath(ENGINE_SOCKET)
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
    client: EngineClientConfig = EngineClientConfig()
    logging: EngineLoggingConfig = EngineLoggingConfig()

    @model_serializer(when_used='json')
    def only_logging_serialize(self) -> Dict[str, Any]:
        """Serialize the EngineConfig model to include only the logging field when used in JSON serialization.

        Returns
        -------
        Dict[str, Any]
            A dictionary containing only the logging configuration.
        """
        return {'logging': self.logging}
