from pydantic import BaseModel, PositiveInt
from typing import List

from wazuh.core.config.models.ssl_config import IndexerSSLConfig


class IndexerConfig(BaseModel):
    #host: List[str] = ["localhost:9200"] #TODO(26356) - How to handle multiples Indexers
    host: str
    port: PositiveInt
    user: str
    password: str
    ssl: IndexerSSLConfig = IndexerSSLConfig()
