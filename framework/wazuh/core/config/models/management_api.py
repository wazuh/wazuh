from pydantic import BaseModel, PositiveInt

from wazuh.core.config.models.ssl_config import ManagementAPISSLConfig
from wazuh.core.config.models.logging import LogFileMaxSizeConfig


class ManagementAPIIntervals(BaseModel):
    request_timeout: int = 10


class CorsConfig(BaseModel):
    enabled: bool = False
    source_route: str = "*"
    expose_headers: str = "*"
    allow_headers: str = "*"
    allow_credentials: bool = False


class AccessConfig(BaseModel):
    max_login_attempts: PositiveInt = 50
    block_time: PositiveInt = 300
    max_request_per_minute: PositiveInt = 300


class ManagementAPIConfig(BaseModel):
    host: str = "localhost"
    port: PositiveInt = 55000
    drop_privileges: bool = True
    max_upload_size: PositiveInt = 10485760

    intervals: ManagementAPIIntervals = ManagementAPIIntervals()
    ssl: ManagementAPISSLConfig = ManagementAPISSLConfig()
    logging: LogFileMaxSizeConfig = LogFileMaxSizeConfig()
    cors: CorsConfig = CorsConfig()
    access: AccessConfig = AccessConfig()
