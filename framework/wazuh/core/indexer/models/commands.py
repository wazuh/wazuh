from dataclasses import dataclass
from enum import Enum
from typing import List

from pydantic import BaseModel

@dataclass
class Agent:
    """Agent data model in the context of commands."""
    id: str


class Status(Enum):
    """Command execution status."""
    PENDING = 'pending'
    SENT = 'sent'
    COMPLETED = 'completed'
    FAILED = 'failed'


@dataclass
class Command(BaseModel):
    """Command data model."""
    args: List[str]
    agent: Agent
    status: Status
    info: str
