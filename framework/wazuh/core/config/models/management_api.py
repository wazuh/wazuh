from pydantic import BaseModel, PositiveInt
from typing import Literal


from wazuh.core.config.models.ssl_config import APISSLConfig
from wazuh.core.config.models.logging import LoggingWithRotationConfig


class ManagementAPIIntervals(BaseModel):
    """Configuration for management API intervals.

    Parameters
    ----------
    request_timeout : int
        The timeout for requests in seconds. Default is 10.
    """
    request_timeout: int = 10


class CorsConfig(BaseModel):
    """Configuration for Cross-Origin Resource Sharing (CORS).

    Parameters
    ----------
    enabled : bool
        Whether CORS is enabled. Default is False.
    source_route : str
        The source route for CORS requests. Default is "*".
    expose_headers : str
        Headers that are exposed to the client. Default is "*".
    allow_headers : str
        Headers that are allowed in requests. Default is "*".
    allow_credentials : bool
        Whether to allow credentials in CORS requests. Default is False.
    """
    enabled: bool = False
    source_route: str = "*"
    expose_headers: str = "*"
    allow_headers: str = "*"
    allow_credentials: bool = False


class AccessConfig(BaseModel):
    """Configuration for access control settings.

    Parameters
    ----------
    max_login_attempts : PositiveInt
        The maximum number of failed login attempts allowed. Default is 50.
    block_time : PositiveInt
        The duration in seconds to block an IP after reaching the maximum login attempts. Default is 300.
    max_request_per_minute : PositiveInt
        The maximum number of requests allowed per minute. Default is 300.
    """
    max_login_attempts: PositiveInt = 50
    block_time: PositiveInt = 300
    max_request_per_minute: PositiveInt = 300


class ManagementAPIConfig(BaseModel):
    """Configuration for the management API.

    Parameters
    ----------
    host : str
        The host address for the management API. Default is "0.0.0.0".
    port : PositiveInt
        The port number for the management API. Default is 55000.
    drop_privileges : bool
        Whether to drop privileges after starting the API. Default is True.
    max_upload_size : PositiveInt
        The maximum upload size in bytes. Default is 10485760 (10 MB).
    jwt_expiration_timeout : PositiveInt
        The expiration timeout for JWT in seconds. Default is 900.
    rbac_mode : Literal["black", "white"]
        The role-based access control mode. Default is "white".
    intervals : ManagementAPIIntervals
        Configuration for management API intervals. Default is an instance of ManagementAPIIntervals.
    ssl : APISSLConfig
        SSL configuration for the management API. Default is an instance of APISSLConfig.
    logging : LoggingWithRotationConfig
        Logging configuration for the management API. Default is an instance of LoggingWithRotationConfig.
    cors : CorsConfig
        CORS configuration for the management API. Default is an instance of CorsConfig.
    access : AccessConfig
        Access configuration for the management API. Default is an instance of AccessConfig.
    """
    host: str = "0.0.0.0"
    port: PositiveInt = 55000
    drop_privileges: bool = True
    max_upload_size: PositiveInt = 10485760
    jwt_expiration_timeout: PositiveInt = 900
    rbac_mode: Literal["black", "white"] = "white"

    intervals: ManagementAPIIntervals = ManagementAPIIntervals()
    ssl: APISSLConfig = APISSLConfig(
        key="/var/ossec/api/configuration/ssl/server.key",
        cert="/var/ossec/api/configuration/ssl/server.crt"
    )
    logging: LoggingWithRotationConfig = LoggingWithRotationConfig()
    cors: CorsConfig = CorsConfig()
    access: AccessConfig = AccessConfig()
