from pydantic import BaseModel, PositiveInt, PositiveFloat, FilePath

from wazuh.core.config.models.ssl_config import SSLConfig
from wazuh.core.config.models.logging import LoggingConfig


class BatcherConfig(BaseModel):
    max_elements: PositiveInt = 5
    max_size: PositiveInt = 3000
    wait_time: PositiveFloat = 0.15


class CommsAPIFilesConfig(BaseModel):
    path: FilePath = "/files"


class CommsAPIConfig(BaseModel):
    host: str = "localhost"
    port: PositiveInt = 27000
    workers: PositiveInt = 2

    logging: LoggingConfig = LoggingConfig()
    batcher: BatcherConfig = BatcherConfig()
    ssl: SSLConfig = SSLConfig(
        key="/var/ossec/etc/server.key",
        cert="/var/ossec/etc/server.crt",
        ca="/var/ossec/etc/sslmanager.ca",
    )
    files: CommsAPIFilesConfig = CommsAPIFilesConfig()
