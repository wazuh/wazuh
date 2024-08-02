from dataclasses import dataclass
from datetime import datetime

from uuid6 import uuid7


@dataclass
class Agent:
    """Representation of a Wazuh Agent."""

    id: uuid7
    name: str
    key: str
    groups: str = None
    type: str = None
    version: str = None
    last_login: datetime = None
    persistent_connection_node: str = None
