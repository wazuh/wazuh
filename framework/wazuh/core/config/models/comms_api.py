import os.path
from pydantic import PositiveInt, PositiveFloat

from api.constants import API_SSL_PATH
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.ssl_config import APISSLConfig
from wazuh.core.config.models.logging import APILoggingConfig

DEFAULT_COMMUNICATIONS_API_KEY_PATH = os.path.join(API_SSL_PATH, 'server.key')
DEFAULT_COMMUNICATIONS_API_CERT_PATH = os.path.join(API_SSL_PATH, 'server.crt')


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
        key=DEFAULT_COMMUNICATIONS_API_KEY_PATH,
        cert=DEFAULT_COMMUNICATIONS_API_CERT_PATH,
        ssl_ciphers=""
    )
