from pydantic import ValidationInfo, field_validator
from wazuh.core.config.models.base import ValidateFilePathMixin, WazuhConfigBaseModel
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


class JWTConfig(WazuhConfigBaseModel, ValidateFilePathMixin):
    """Configuration for JWT key pair.

    Parameters
    ----------
    private_key : str
        The path to the private JTW key file.
    _public_key : str
        The public JWT key.
    """

    private_key: str = ''
    _public_key: str = ''

    def get_public_key(self) -> str:
        """Retrieve the stored public key.

        Returns
        -------
        str
            Public key string.
        """
        return self._public_key

    def set_public_key(self, public_key: str):
        """Set the public key.

        Parameters
        ----------
        public_key : str
            The public key to be set.
        """
        self._public_key = public_key

    @field_validator('private_key')
    @classmethod
    def validate_key_files(cls, path: str, info: ValidationInfo) -> str:
        """Validate that the private key file exists if the path is not empty.

        Parameters
        ----------
        path : str
            Path to the JTW key.
        info : ValidationInfo
            Validation context information.

        Raises
        ------
        ValueError
            Invalid JWT file path.

        Returns
        -------
        str
            JWT key path.
        """
        cls._validate_file_path(path, info.field_name)
        return path


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
    jwt : JWTConfig
        JWT key pair configuration.
    """

    update_check: bool = False
    logging: LoggingConfig = LoggingConfig(level=LoggingLevel.info)
    cti: CTIConfig = CTIConfig()
    jwt: JWTConfig = JWTConfig()
