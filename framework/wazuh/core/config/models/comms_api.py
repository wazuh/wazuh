from pydantic import BaseModel, PositiveInt, PositiveFloat, FilePath

from wazuh.core.config.models.ssl_config import APISSLConfig
from wazuh.core.config.models.logging import LoggingWithRotationConfig


class BatcherConfig(BaseModel):
    """Configuration for the Batcher.

    Parameters
    ----------
    max_elements : PositiveInt
        The maximum number of elements in the batch. Default: 5.
    max_size : PositiveInt
        The maximum size in bytes of the batch. Default: 3000.
    wait_time : PositiveFloat
        The time in seconds to wait before sending the batch. Default: 0.15.
    """
    max_elements: PositiveInt = 5
    max_size: PositiveInt = 3000
    wait_time: PositiveFloat = 0.15


class CommsAPIIntervals(BaseModel):
    """Configuration for the communication API intervals.

    Parameters
    ----------
    request_timeout : int
        The timeout duration for requests in seconds. Default: 10.
    """
    request_timeout: int = 10


class CommsAPIConfig(BaseModel):
    """Configuration for the Communications API.

    Parameters
    ----------
    host : str
        The host address for the communications API. Default: "localhost".
    port : PositiveInt
        The port number for the communications API. Default: 27000.
    workers : PositiveInt
        The number of worker threads for the communications API. Default: 4.
    logging : LoggingWithRotationConfig
        Logging configuration for the communications API. Default is an instance of LoggingWithRotationConfig.
    batcher : BatcherConfig
        Configuration for the batcher. Default is an instance of BatcherConfig.
    intervals : CommsAPIIntervals
        Configuration for the API intervals. Default is an instance of CommsAPIIntervals.
    ssl : APISSLConfig
        SSL configuration for the communications API. Default is an instance of APISSLConfig.
    """
    host: str = "localhost"
    port: PositiveInt = 27000
    workers: PositiveInt = 4

    logging: LoggingWithRotationConfig = LoggingWithRotationConfig()
    batcher: BatcherConfig = BatcherConfig()
    intervals: CommsAPIIntervals = CommsAPIIntervals()
    ssl: APISSLConfig = APISSLConfig(
        key="/var/ossec/api/configuration/ssl/server.key",
        cert="/var/ossec/api/configuration/ssl/server.crt",
        ssl_ciphers=""
    )
