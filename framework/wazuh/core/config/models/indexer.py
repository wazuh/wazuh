from typing import List

from pydantic import Field, PositiveInt, field_serializer
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.ssl_config import IndexerSSLConfig


class IndexerNode(WazuhConfigBaseModel):
    """Indexer instance connection configuration.

    Parameters
    ----------
    host : str
        The host address of the indexer.
    port : PositiveInt
        The port number for the indexer.
    """

    host: str
    port: PositiveInt


class IndexerConfig(WazuhConfigBaseModel):
    """Configuration for the Indexer.

    Parameters
    ----------
    hosts : List[IndexerNode]
        List of nodes configuration.
    username : str
        The username for indexer authentication.
    password : str
        The password for indexer authentication.
    ssl : IndexerSSLConfig, optional
        SSL configuration for the indexer. Default is None.
    """

    hosts: List[IndexerNode] = Field(min_length=1)
    username: str
    password: str
    ssl: IndexerSSLConfig = None

    @field_serializer('hosts', when_used='json')
    def convert_hosts_to_str(self, hosts: List[IndexerNode], _info) -> List[str]:
        """Convert the list of IndexerNode objects to a list of strings for JSON serialization.

        Parameters
        ----------
        hosts : List[IndexerNode]
            List of IndexerNode objects to be converted.
        _info : SerializationInfo
            Additional serialization context (provided by Pydantic).

        Returns
        -------
        List[str]
            List of strings with the format '<scheme>://<host>:<port>'.
        """
        final_list = []
        scheme = 'https' if self.ssl.use_ssl else 'http'

        for node in hosts:
            final_list.append(f'{scheme}://{node.host}:{node.port}')

        return final_list
