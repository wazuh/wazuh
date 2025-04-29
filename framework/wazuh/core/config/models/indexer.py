from typing import Any, List

from pydantic import Field, HttpUrl, model_validator
from wazuh.core.common import CLIENT_KEYSTORE
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.ssl_config import IndexerSSLConfig
from wazuh.core.utils import KeystoreReader


class IndexerConfig(WazuhConfigBaseModel):
    """Configuration for the Indexer.

    Parameters
    ----------
    hosts : List[HttpUrl]
        List of nodes configuration.
    username : str
        The username for indexer authentication.
    password : str
        The password for indexer authentication.
    ssl : IndexerSSLConfig, optional
        SSL configuration for the indexer. Default is None.
    """

    _username: str
    _password: str

    hosts: List[HttpUrl] = Field(min_length=1)
    ssl: IndexerSSLConfig = None

    @model_validator(mode='after')
    def validate_hosts_scheme(self) -> 'IndexerConfig':
        """Validate the hosts scheme based on `ssl.use_ssl` is enabled or not.

        Returns
        -------
        IndexerConfig
            The validated instance.

        Raises
        ------
        ValueError
            If the scheme of any of the hosts does not match with the `ssl.use_ssl` value.
        """
        if self.ssl.use_ssl:
            invalid_hosts = [str(host) for host in self.hosts if host.scheme == 'http']
            if invalid_hosts:
                raise ValueError(f'Invalid hosts: {invalid_hosts}, `use_ssl` is enabled but scheme is http.')

        return self

    def model_post_init(self, context: Any):
        """Post initialization of the model.

        Parameters
        ----------
        context : Any
            Initialization context.
        """
        keystore = KeystoreReader(CLIENT_KEYSTORE)

        try:
            self._username = keystore['indexer-username']
            self._password = keystore['indexer-password']
        except KeyError as e:
            raise ValueError(f'The key {e} was not found in the "{CLIENT_KEYSTORE}" keystore.')

    @property
    def username(self) -> str:
        """Get the indexer username.

        Returns
        -------
        str
            The indexer username.
        """
        return self._username

    @property
    def password(self) -> str:
        """Get the password username.

        Returns
        -------
        str
            The indexer password.
        """
        return self._password
