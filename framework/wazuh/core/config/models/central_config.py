from enum import Enum

from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.comms_api import CommsAPIConfig
from wazuh.core.config.models.engine import EngineConfig
from wazuh.core.config.models.indexer import IndexerConfig
from wazuh.core.config.models.management_api import ManagementAPIConfig
from wazuh.core.config.models.server import ServerConfig


class ConfigSections(str, Enum):
    """Enum representing the different sections of the CentralizedConfig."""
    SERVER = 'server'
    INDEXER = 'indexer'
    ENGINE = 'engine'
    MANAGEMENT_API = 'management_api'
    COMMUNICATIONS_API = 'communications_api'

    @classmethod
    def _missing_(cls, value: str) -> None:
        """Missing enum value handler.
        
        Parameters
        ----------
        value : str
            Enum value.
        
        Raises
        ------
        ValueError
            Invalid value error.
        """
        raise ValueError(value)


class Config(WazuhConfigBaseModel):
    """Main configuration class for the application.

    Parameters
    ----------
    server : ServerConfig
        Configuration for the server.
    indexer : IndexerConfig
        Configuration for the indexer.
    engine : EngineConfig, optional
        Configuration for the engine. Default is an instance of EngineConfig.
    management_api : ManagementAPIConfig, optional
        Configuration for the management API. Default is an instance of ManagementAPIConfig.
    communications_api : CommsAPIConfig, optional
        Configuration for the communications API. Default is an instance of CommsAPIConfig.
    """
    server: ServerConfig
    indexer: IndexerConfig
    engine: EngineConfig = EngineConfig()
    management_api: ManagementAPIConfig = ManagementAPIConfig()
    communications_api: CommsAPIConfig = CommsAPIConfig()
