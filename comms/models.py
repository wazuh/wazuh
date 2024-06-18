from pydantic import BaseModel
from typing import List, Dict

class Command(BaseModel):
    id: int
    type: str

class Credentials(BaseModel):
    uuid: str
    key: str

class Event(BaseModel):
    id: int
    data: str
    timestamp: int

class EventsBody(BaseModel):
    events: List[Event]

class GetCommandsResponse(BaseModel):
    commands: List[Command]

class TokenResponse(BaseModel):
    token: str
