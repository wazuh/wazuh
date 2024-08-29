from dataclasses import dataclass
from enum import Enum
from typing import List


@dataclass
class CommandAgent:
    """Agent data model in the context of commands."""
    # TODO(25121): this should be a UUID, but pydantic supports up to v5 only.
    # Related to https://github.com/python/cpython/issues/89083.
    id: str


class Status(str, Enum):
    """Command execution status."""
    PENDING = 'pending'
    SENT = 'sent'
    COMPLETED = 'completed'
    FAILED = 'failed'


@dataclass
class Document:
    """OpenSearch document model."""
    id: str = None


@dataclass
class Result(Document):
    """Command result data model."""
    # Cannot extend enumerations, custom validators are used to prevent agents 
    # from uploading a result with a status other than completed or failed.
    # https://docs.python.org/3/howto/enum.html#restricted-enum-subclassing
    status: Status = None
    info: str = None


@dataclass
class Command(Result):
    """Command data model."""
    args: List[str] = None
    agent: CommandAgent = None

    @classmethod
    def from_dict(cls, id: str, data: dict):
        """Create an object instance from a dictionary.
        
        Parameters
        ----------
        id : str
            Command ID.
        data : dict
            Command data.
        
        Returns
        -------
        Command
            Object instance with its fields initialized.
        """
        return cls(
            id=id,
            args=data.get('args'),
            agent=CommandAgent(id=data.get('agent').get('id')),
            status=Status(data.get('status')),
            info=data.get('info'),
        )
