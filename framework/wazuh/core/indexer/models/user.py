from dataclasses import asdict, dataclass
from datetime import datetime

from wazuh.core.indexer.models.role import Role
from wazuh.core.indexer.utils import convert_enums


@dataclass
class User:
    """User represents an individual who send requests to the API."""

    id: str = None
    name: str = None
    password: str = None
    allow_run_as: bool = None
    roles: list[Role] = None
    created_at: datetime = None

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)
