import yaml
import os
from typing import Optional

from wazuh.core.config.models.central_config import Config, CommsAPIConfig, ManagementAPIConfig, ServerConfig, IndexerConfig

CENTRALIZED_CONFIG_FILE_PATH = "./wazuh-server.yml"


class CentralizedConfig:
    _config: Optional[Config] = None

    @classmethod
    def load(cls):
        if cls._config is None:
            if not os.path.exists(CENTRALIZED_CONFIG_FILE_PATH):
                raise FileNotFoundError(f"Configuration file not found: {CENTRALIZED_CONFIG_FILE_PATH}")
            with open(CENTRALIZED_CONFIG_FILE_PATH, 'r') as file:
                config_data = yaml.safe_load(file)
                cls._config = Config(**config_data)

    @classmethod
    def get_comms_api_config(cls) -> CommsAPIConfig:
        if cls._config is None:
            cls.load()

        return cls._config.communications_api

    @classmethod
    def get_management_api_config(cls) ->  ManagementAPIConfig:
        if cls._config is None:
            cls.load()

        return cls._config.management

    @classmethod
    def get_indexer_config(cls) -> IndexerConfig:
        if cls._config is None:
            cls.load()

        return cls._config.indexer

    @classmethod
    def get_server_config(cls) -> ServerConfig:
        if cls._config is None:
            cls.load()

        return cls._config.server


print(CentralizedConfig.get_server_config())
print(CentralizedConfig.get_comms_api_config())