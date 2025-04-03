import base64
from dataclasses import InitVar, asdict, dataclass
from datetime import datetime
from enum import Enum
from hmac import compare_digest
from typing import List

from wazuh.core.indexer.utils import convert_enums, generate_salt, hash_key


class Status(str, Enum):
    """Agent connection status enum."""

    ACTIVE = 'active'
    DISCONNECTED = 'disconnected'
    NEVER_CONNECTED = 'never_connected'


@dataclass
class OS:
    """Agent operating system information."""

    name: str = None
    type: str = None
    version: str = None


@dataclass
class Host:
    """Agent host information."""

    architecture: str = None
    hostname: str = None
    ip: List[str] = None
    os: OS = None


@dataclass
class Agent:
    """Representation of a Wazuh Agent."""

    id: str = None
    name: str = None
    key: str = None
    type: str = None
    version: str = None
    groups: List[str] | None = None
    last_login: datetime = None
    status: Status = None
    host: Host = None

    raw_key: InitVar[str | None] = None

    def __post_init__(self, raw_key: str | None):
        if raw_key is not None:
            self.key = self.hash_key(raw_key).decode('latin-1')

    @staticmethod
    def hash_key(raw_key: str) -> bytes:
        """Generate a hash value from the given raw key.

        Parameters
        ----------
        raw_key : str
            Key to hash.

        Returns
        -------
        str
            Hashed key value.
        """
        salt = generate_salt()
        key_hash = hash_key(raw_key, salt)
        return base64.b64encode(salt + key_hash)

    def check_key(self, key: str) -> bool:
        """Validate the given key with the stored hash key.

        Parameters
        ----------
        key : str
            Value to check.

        Returns
        -------
        bool
            True if the hashes are equal, else False.
        """
        stored_key = self.key.encode('latin-1')
        stored_key = base64.b64decode(stored_key)
        salt, key_hash = stored_key[:16], stored_key[16:]
        return compare_digest(key_hash, hash_key(key, salt))

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)
