from pydantic import PositiveFloat, PositiveInt
from server_management_api.constants import API_CERT_PATH, API_KEY_PATH
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.logging import APILoggingConfig
from wazuh.core.config.models.ssl_config import APISSLConfig


class BatcherConfig(WazuhConfigBaseModel):
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


class CommsAPIConfig(WazuhConfigBaseModel):
    """Configuration for the Communications API.

    Parameters
    ----------
    host : str
        The host address for the communications API. Default: "localhost".
    port : PositiveInt
        The port number for the communications API. Default: 27000.
    workers : PositiveInt
        The number of worker threads for the communications API. Default: 4.
    logging : APILoggingConfig
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

    logging: APILoggingConfig = APILoggingConfig()
    batcher: BatcherConfig = BatcherConfig()
    ssl: APISSLConfig = APISSLConfig(
        key=API_KEY_PATH.as_posix(),
        cert=API_CERT_PATH.as_posix(),
        ssl_ciphers=""
    )
