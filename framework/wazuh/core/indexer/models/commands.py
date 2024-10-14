from dataclasses import dataclass
from enum import Enum
from typing import List


@dataclass
class Action:
    """Command action data model."""
    name: str
    args: List[str]
    version: str


@dataclass
class Result:
    """Command result data model."""
    info: str = None
    code: int = None
    message: str = None
    data: str = None


class Source(str, Enum):
    """Command source data model."""
    SERVICES = 'Users/Services'
    ENGINE = 'Engine'
    CONTENT_MANAGER = 'Content manager'


class Status(str, Enum):
    """Command status data model."""
    PENDING = 'pending'
    SENT = 'sent'
    SUCCESS = 'success'
    FAILED = 'failed'


class Type(str, Enum):
    """Command target type data model."""
    AGENT = 'agent'
    GROUP = 'group'
    SERVER = 'server'


@dataclass
class Target:
    """Command target data model."""
    # TODO(25121): this should be a UUID, but pydantic supports up to v5 only.
    # Related to https://github.com/python/cpython/issues/89083.
    id: str
    type: Type


@dataclass
class Command:
    """Command data model."""
    document_id: str = None
    request_id: str = None
    order_id: str = None
    groups: str = None
    source: Source = None
    user: str = None
    target: Target = None
    action: Action = None
    timeout: int = None
    status: Status = None
    result: Result = None

    @classmethod
    def from_dict(cls, document_id: str, data: dict):
        """Create an object instance from a dictionary.
        
        Parameters
        ----------
        document_id : str
            Document ID.
        data : dict
            Command data.
        
        Returns
        -------
        Command
            Object instance with its fields initialized.
        """
        return cls(
            document_id=document_id,
            order_id=data.get('order_id'),
            request_id=data.get('request_id'),
            groups=data.get('groups'),
            source=Source(data.get('source')) if 'source' in data else None,
            user=data.get('user'),
            target=Target(
                id=data.get('target').get('id'),
                type=Type(data.get('target').get('type')),
            ) if 'target' in data else None,
            action=Action(
                name=data.get('action').get('name'),
                args=data.get('action').get('args'),
                version=data.get('action').get('version'),
            ) if 'action' in data else None,
            timeout=data.get('timeout'),
            status=Status(data.get('status')) if 'status' in data else None,
            result=Result(
                info=data.get('result').get('info'),
                code=data.get('result').get('code'),
                message=data.get('result').get('message'),
                data=data.get('result').get('data'),
            ) if 'result' in data else None,
        )
