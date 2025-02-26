from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum

from wazuh.core.indexer.utils import convert_enums


class Effect(str, Enum):
    """RBAC policy effect."""

    ALLOW = 'allow'
    DENY = 'deny'


@dataclass
class Policy:
    """Policy holds a detailed sets of permissions specifying allowed actions on resources."""

    id: str = None
    name: str = None
    level: int = None
    actions: list[str] = None
    resources: list[str] = None
    effect: str = None
    created_at: datetime = None

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)
