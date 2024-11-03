from pydantic import BaseModel, PositiveInt
from typing import List

from wazuh.core.config.models.ssl_config import IndexerSSLConfig


#TODO(26356) - Check with Indexer team if this is useful
class IndexesConfig(BaseModel):
    alert: str = "wazuh-alerts-5.x"
    agents: str = "agents-index"
    commands: str = "commands-index"
    events: str = "events-index"


class IndexerConfig(BaseModel):
    #host: List[str] = ["localhost:9200"] #TODO(26356) - How to handle multiples Indexers
    host: str = "wazuh-indexer"
    port: PositiveInt = 9200
    user: str = "admin"
    password: str = "SecretPassword1%"
    indexes: IndexesConfig = IndexesConfig()
    ssl: IndexerSSLConfig = IndexerSSLConfig()
