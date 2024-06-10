from pydantic import BaseModel
from typing import List

class Command(BaseModel):
    id: int
    type: str
    agent_ids: list

class Event(BaseModel):
    id: int
    data: str
    timestamp: int

class Login(BaseModel):
    uuid: str
    password: str

class PostCommandsBody(BaseModel):
    commands: List[Command]

class PostEventsBody(BaseModel):
    events: List[Event]
