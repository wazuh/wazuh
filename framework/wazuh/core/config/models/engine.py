from pydantic import BaseModel, FilePath, PositiveInt, PositiveFloat
from wazuh.core.config.models.logging import LoggingConfig


# TODO(#25121): Change the socket path once the Cpp team does it
class EngineClientConfig(BaseModel):
    api_socket_path: FilePath = "/var/wazuh/queue/engine.sock"
    retries: PositiveInt = 3
    timeout: PositiveFloat = 10


class EngineConfig(BaseModel):
    tzdv_automatic_update: bool = False
    client: EngineClientConfig() = EngineClientConfig()
    logging: LoggingConfig = LoggingConfig()
