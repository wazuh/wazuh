from dataclasses import asdict, dataclass
from datetime import datetime

from wazuh.core.indexer.utils import convert_enums


@dataclass
class Policy:
    """Policy holds a detailed sets of permissions specifying allowed actions on resources."""

    id: str = None
    name: str = None
    level: int = None
    policy: str = None
    created_at: datetime = None


@dataclass
class Rule:
    """Rule defines conditions under which policies apply."""

    id: str = None
    name: str = None
    rule: str = None
    created_at: datetime = None


@dataclass
class Role:
    """Role encapsulates access rights for the users."""

    id: str = None
    name: str = None
    level: int = None
    policies: list[Policy] = None
    rules: list[Rule] = None
    created_at: datetime = None

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)
