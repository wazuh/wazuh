from pydantic import BaseModel
from typing import List

class Command(BaseModel):
    id: int
    type: str

class Event(BaseModel):
    id: int
    data: str
    timestamp: int

class Login(BaseModel):
    uuid: str
    key: str

class StatelessEventsBody(BaseModel):
    events: List[Event]

class GetCommandsResponse(BaseModel):
    commands: List[Command]

class TokenResponse(BaseModel):
    token: str

class Message(BaseModel):
    message: str
