from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated

from auth import JWTBearer, generate_token, decode_token
from commands_manager import commands_manager
from models import PostEventsBody, Login

router = APIRouter(prefix="/api/v1")


@router.post("/login")
async def login(login: Login):
    # TODO: validate credentials with the indexer
    token = generate_token(login.uuid)
    return {"token": token}

@router.post("/events/stateless", dependencies=[Depends(JWTBearer())])
async def post_stateless_events(body: PostEventsBody):
    # TODO: send event to the engine
    _ = body.events
    return {"message": "Events received"}

@router.get("/commands")
async def get_commands(token: Annotated[str, Depends(JWTBearer())]):
    decoded_token = decode_token(token)
    commands = await commands_manager.get_commands(decoded_token["uuid"])
    if commands:
        return {"commands": commands}
    else:
        raise HTTPException(502, {"message": "No commands found"})
