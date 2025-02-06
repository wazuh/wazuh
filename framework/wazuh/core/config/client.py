import os
from typing import List, Optional

import yaml
from pydantic import ValidationError
from wazuh import WazuhInternalError
from wazuh.core.common import WAZUH_SERVER_YML
from wazuh.core.config.models.central_config import (
    CommsAPIConfig,
    Config,
    ConfigSections,
    EngineConfig,
    IndexerConfig,
    ManagementAPIConfig,
    ServerConfig,
)
from wazuh.core.config.models.management_api import RBACMode
from wazuh.core.config.models.server import ServerSyncConfig


class CentralizedConfig:
    """Class to manage centralized configuration loading and access.

    Attributes
    ----------
    _config : Optional[Config]
        The loaded configuration object, initialized as None.
    """

    _config: Optional[Config] = None

    @classmethod
    def load(cls):
        """Load the configuration from the YAML file.

        Raises
        ------
        FileNotFoundError
            If the configuration file does not exist.
        """
        if cls._config is None:
            if not os.path.exists(WAZUH_SERVER_YML):
                raise FileNotFoundError(f'Configuration file not found: {WAZUH_SERVER_YML}')
            with open(WAZUH_SERVER_YML, 'r') as file:
                config_data = yaml.safe_load(file)
                cls._config = Config(**config_data)

    @classmethod
    def get_comms_api_config(cls) -> CommsAPIConfig:
        """Retrieve the communications API configuration.

        Loads the configuration if it has not been loaded yet.

        Returns
        -------
        CommsAPIConfig
            The communications API configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.communications_api

    @classmethod
    def get_management_api_config(cls) -> ManagementAPIConfig:
        """Retrieve the management API configuration.

         Loads the configuration if it has not been loaded yet.

        Returns
        -------
        ManagementAPIConfig
            The management API configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.management_api

    @classmethod
    def get_indexer_config(cls) -> IndexerConfig:
        """Retrieve the indexer configuration.

        Loads the configuration if it has not been loaded yet.

        Returns
        -------
        IndexerConfig
            The indexer configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.indexer

    @classmethod
    def get_engine_config(cls) -> EngineConfig:
        """Retrieve the engine configuration.

        Loads the configuration if it has not been loaded yet.

        Returns
        -------
        EngineConfig
            The engine configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.engine

    @classmethod
    def get_server_config(cls) -> ServerConfig:
        """Retrieve the server configuration.

        Loads the configuration if it has not been loaded yet.

        Returns
        -------
        ServerConfig
            The server configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.server

    @classmethod
    def get_internal_server_config(cls) -> ServerSyncConfig:
        """Retrieve the internal server configuration.

        Loads the configuration if it has not been loaded yet.

        Returns
        -------
        ServerSyncConfig
            The internal server configuration.
        """
        if cls._config is None:
            cls.load()

        return cls._config.server.get_internal_config()

    @classmethod
    def get_config_json(cls, sections: Optional[List[ConfigSections]] = None) -> str:
        """Retrieve the current configuration as a JSON str, optionally filtered by specified sections.

        Parameters
        ----------
        sections : Optional[List[ConfigSections]]
            List of configuration sections to retrieve. If None, all sections are included.

        Returns
        -------
        str
            A string containing the configuration values in JSON.
        """
        if cls._config is None:
            cls.load()

        if sections is None:
            return cls._config.model_dump_json()
        else:
            return cls._config.model_dump_json(include=[section.value for section in sections])

    @classmethod
    def update_security_conf(cls, config: dict):
        """Update the security configuration with the provided values.

        This method updates the security-related settings, including the
        authentication token expiration timeout and the RBAC mode, then writes
        the changes back to the YAML configuration file.

        Parameters
        ----------
        config : dict
            A dictionary containing the security-related configuration settings,
            such as "auth_token_exp_timeout" and "rbac_mode".

        Raises
        ------
        WazuhInternalError
            If an error occurs while updating the configuration or saving
            to the file.
        """
        if cls._config is None:
            cls.load()

        if config['auth_token_exp_timeout'] is not None:
            cls._config.management_api.jwt_expiration_timeout = config['auth_token_exp_timeout']

        if config['rbac_mode'] is not None:
            cls._config.management_api.rbac_mode = RBACMode(config['rbac_mode'])

        non_default_values = cls._config.model_dump(exclude_defaults=True)

        try:
            with open(WAZUH_SERVER_YML, 'w') as file:
                yaml.dump(non_default_values, file)
        except IOError:
            raise WazuhInternalError(1005)
        except ValidationError:
            raise WazuhInternalError(1103)
