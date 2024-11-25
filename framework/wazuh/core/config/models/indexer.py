from pydantic import PositiveInt, Field, field_serializer
from typing import List

from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.ssl_config import IndexerSSLConfig


class IndexerNode(WazuhConfigBaseModel):
    """Configuration for the Indexer node

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
    user : str
        The username for indexer authentication.
    password : str
        The password for indexer authentication.
    ssl : IndexerSSLConfig, optional
        SSL configuration for the indexer. Default is None.
    """
    hosts: List[IndexerNode] = Field(min_length=1)
    user: str
    password: str
    ssl: IndexerSSLConfig = None

    @field_serializer('hosts', when_used='json')
    def convert_hosts_to_str(self, hosts: List[IndexerNode], _info) -> List[str]:
        final_list = []

        for node in hosts:
            final_list.append(f'{node.host}:{node.port}')

        return final_list
