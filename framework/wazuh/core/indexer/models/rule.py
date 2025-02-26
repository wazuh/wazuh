from dataclasses import asdict, dataclass
from datetime import datetime

from wazuh.core.indexer.utils import convert_enums


@dataclass
class Rule:
    """Rule defines conditions under which policies apply."""

    id: str = None
    name: str = None
    body: dict = None
    created_at: datetime = None

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)
