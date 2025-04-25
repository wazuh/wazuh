from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.logging import LoggingConfig, LoggingLevel

DEFAULT_CTI_URL = 'https://cti.wazuh.com'


class CTIConfig(WazuhConfigBaseModel):
    """Configuration for CTI settings.

    Parameters
    ----------
    update_check : bool
        Whether to perform an update check. Default is True.
    url : str
        The URL for the CTI service. Default is "https://cti.wazuh.com".
    """

    update_check: bool = True
    url: str = DEFAULT_CTI_URL


class ServerConfig(WazuhConfigBaseModel):
    """Configuration for the server.

    Parameters
    ----------
    update_check : bool
        Whether to perform an update check. Default is False.
    logging : LoggingConfig
        Logging configuration. Default is LoggingConfig(level="debug2").
    cti : CTIConfig
        Configuration for CTI settings. Default is CTIConfig().
    """

    update_check: bool = False
    logging: LoggingConfig = LoggingConfig(level=LoggingLevel.info)
    cti: CTIConfig = CTIConfig()
