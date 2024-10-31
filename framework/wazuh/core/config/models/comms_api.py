from pydantic import BaseModel, PositiveInt, PositiveFloat, FilePath

from wazuh.core.config.models.ssl_config import APISSLConfig
from wazuh.core.config.models.logging import LoggingWithRotationConfig


class BatcherConfig(BaseModel):
    max_elements: PositiveInt = 5
    max_size: PositiveInt = 3000
    wait_time: PositiveFloat = 0.15


class CommsAPIConfig(BaseModel):
    host: str = "localhost"
    port: PositiveInt = 27000
    workers: PositiveInt = 4

    logging: LoggingWithRotationConfig = LoggingWithRotationConfig()
    batcher: BatcherConfig = BatcherConfig()
    ssl: APISSLConfig = APISSLConfig(
        key="/var/ossec/api/configuration/ssl/server.key",
        cert="/var/ossec/api/configuration/ssl/server.crt",
        ca="/etc/ssl/certs/ca-certificates.crt",
        ssl_ciphers=""
    )
