from pydantic import BaseModel, PositiveInt

from wazuh.core.config.models.ssl_config import IndexerSSLConfig


class IndexerConfig(BaseModel):
    host: str
    port: PositiveInt
    user: str
    password: str
    ssl: IndexerSSLConfig = IndexerSSLConfig()
