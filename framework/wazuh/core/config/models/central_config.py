from pydantic import BaseModel

from wazuh.core.config.models.server import ServerConfig
from wazuh.core.config.models.indexer import IndexerConfig
from wazuh.core.config.models.management_api import ManagementAPIConfig
from wazuh.core.config.models.comms_api import CommsAPIConfig


class Config(BaseModel):
    server: ServerConfig = ServerConfig()
    indexer: IndexerConfig = IndexerConfig()
    management: ManagementAPIConfig = ManagementAPIConfig()
    communications_api: CommsAPIConfig = CommsAPIConfig()
