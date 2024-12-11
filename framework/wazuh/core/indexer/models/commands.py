from dataclasses import dataclass
from enum import Enum
from typing import List


@dataclass
class Action:
    """Command action data model."""
    name: str
    version: str
    args: List[str] = None


@dataclass
class Result:
    """Command result data model."""
    code: int = None
    message: str = None
    data: str = None


class Source(str, Enum):
    """Command source enum."""
    SERVICES = 'Users/Services'
    ENGINE = 'Engine'
    CONTENT_MANAGER = 'Content manager'


class Status(str, Enum):
    """Command status enum."""
    PENDING = 'pending'
    SENT = 'sent'
    SUCCESS = 'success'
    FAILED = 'failed'


class TargetType(str, Enum):
    """Command target type enum."""
    AGENT = 'agent'
    GROUP = 'group'
    SERVER = 'server'


@dataclass
class Target:
    """Command target data model."""
    # TODO(25121): this should be a UUID, but pydantic supports up to v5 only.
    # Related to https://github.com/python/cpython/issues/89083.
    id: str
    type: TargetType


@dataclass
class Command:
    """Command data model."""
    document_id: str = None
    request_id: str = None
    order_id: str = None
    source: Source = None
    user: str = None
    target: Target = None
    action: Action = None
    timeout: int = None
    status: Status = None
    result: Result = None

    def __post_init__(self):
        if isinstance(self.target, dict):
            self.target = Target(**self.target)
        if isinstance(self.action, dict):
            self.action = Action(**self.action)
        if isinstance(self.result, dict):
            self.result = Result(**self.result)


class ResponseResult(str, Enum):
    """Create command response result enum."""
    CREATED = 'CREATED'
    OK = 'OK'
    ACCEPTED = 'Accepted'
    INTERNAL_ERROR = 'Internal Error'
    NOT_FOUND = 'Not found'


@dataclass
class CreateCommandResponse:
    """Create command response data model."""
    index: str
    document_ids: List[str]
    result: ResponseResult
