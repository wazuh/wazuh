from base64 import b64decode, b64encode
from dataclasses import InitVar, asdict, dataclass
from datetime import datetime
from enum import Enum
from hmac import compare_digest

from wazuh.core.indexer.utils import convert_enums, generate_salt, hash_key


class Effect(str, Enum):
    """RBAC policy effect."""

    ALLOW = 'allow'
    DENY = 'deny'


@dataclass
class Policy:
    """Policy holds a detailed sets of permissions specifying allowed actions on resources."""

    name: str = None
    level: int = None
    actions: list[str] = None
    resources: list[str] = None
    effect: Effect = None


@dataclass
class Rule:
    """Rule defines conditions under which policies apply."""

    name: str = None
    body: dict = None


@dataclass
class Role:
    """Role encapsulates access rights for the users."""

    name: str = None
    level: int = None
    policies: list[Policy] = None
    rules: list[Rule] = None

    def __post_init__(self):
        if isinstance(self.policies, (list, tuple)):
            setattr(self, 'policies', [Policy(**x) if isinstance(x, dict) else x for x in self.policies])

        if isinstance(self.rules, (list, tuple)):
            setattr(self, 'rules', [Rule(**x) if isinstance(x, dict) else x for x in self.rules])


@dataclass
class User:
    """User represents an individual who send requests to the API."""

    id: str = None
    name: str = None
    password: str = None
    allow_run_as: bool = None
    roles: list[Role] = None
    created_at: datetime = None

    raw_password: InitVar[str | None] = None

    def __post_init__(self, raw_password: str | None):
        if raw_password is not None:
            salt = generate_salt()
            key_hash = hash_key(raw_password, salt)
            self.password = b64encode(salt + key_hash).decode('latin-1')

        if isinstance(self.roles, (list, tuple)):
            setattr(self, 'roles', [Role(**x) if isinstance(x, dict) else x for x in self.roles])

    def to_dict(self) -> dict:
        """Translate the instance to a dictionary ready to be indexed.

        Returns
        -------
        dict
            The translated data.
        """
        return asdict(self, dict_factory=convert_enums)

    def check_password(self, password: str) -> bool:
        """Validate the given password with the stored hash password.

        Parameters
        ----------
        password : str
            Value to check.

        Returns
        -------
        bool
            True if the hashes are equal, else False.
        """
        stored_key = self.password.encode('latin-1')
        stored_key = b64decode(stored_key)
        salt, key_hash = stored_key[:16], stored_key[16:]
        return compare_digest(key_hash, hash_key(password, salt))
