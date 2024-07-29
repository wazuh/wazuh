from dataclasses import dataclass

from uuid6 import uuid7


@dataclass
class Agent:
    """Representation of a Wazuh Agent."""

    uuid: uuid7
    password: str
    name: str
