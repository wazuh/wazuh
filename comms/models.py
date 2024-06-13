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

class PostEventsBody(BaseModel):
    events: List[Event]
