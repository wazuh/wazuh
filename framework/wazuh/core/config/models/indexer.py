from pydantic import BaseModel, PositiveInt

from wazuh.core.config.models.ssl_config import IndexerSSLConfig


class IndexerConfig(BaseModel):
    """Configuration for the Indexer.

    Parameters
    ----------
    host : str
        The host address of the indexer.
    port : PositiveInt
        The port number for the indexer.
    user : str
        The username for indexer authentication.
    password : str
        The password for indexer authentication.
    ssl : IndexerSSLConfig, optional
        SSL configuration for the indexer. Default is an instance of IndexerSSLConfig.
    """
    host: str
    port: PositiveInt
    user: str
    password: str
    ssl: IndexerSSLConfig = IndexerSSLConfig()
