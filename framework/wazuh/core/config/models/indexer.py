from pydantic import BaseModel, FilePath
from typing import List

from wazuh.core.config.models.ssl_config import SSLConfig


class IndexesConfig(BaseModel):
    alert: str = "wazuh-alerts-5.x"
    agents: str = "agents-index"
    commands: str = "commands-index"
    events: str = "events-index"


class IndexerConfig(BaseModel):
    host: List[str] = ["localhost:9200"]
    user: str = "admin"
    password: str = "admin"
    indexes: IndexesConfig = IndexesConfig()
    ssl: SSLConfig = SSLConfig(
        key="/etc/ssl/certs/key.pem",
        cert="/etc/ssl/certs/cert.pem",
        ca="/etc/ssl/certs/ca.pem"
    )
