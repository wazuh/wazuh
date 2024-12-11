from pydantic import BaseModel


class Credentials(BaseModel):
    uuid: str
    key: str


class TokenResponse(BaseModel):
    token: str
