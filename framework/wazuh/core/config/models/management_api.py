from pydantic import BaseModel, PositiveInt
from typing import Literal


from wazuh.core.config.models.ssl_config import APISSLConfig
from wazuh.core.config.models.logging import LoggingWithRotationConfig


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
    jwt_expiration_timeout: PositiveInt = 900
    rbac_mode: Literal["black", "white"] = "white"

    intervals: ManagementAPIIntervals = ManagementAPIIntervals()
    ssl: APISSLConfig = APISSLConfig(
        key="server.key",
        cert="server.crt"
    )
    logging: LoggingWithRotationConfig = LoggingWithRotationConfig()
    cors: CorsConfig = CorsConfig()
    access: AccessConfig = AccessConfig()
