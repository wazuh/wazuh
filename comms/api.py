from fastapi import APIRouter, Depends, HTTPException, status
from hmac import compare_digest
import opensearchpy
from typing import Annotated

from auth import JWTBearer, generate_token, decode_token
from commands_manager import commands_manager
from models import PostEventsBody, Login
from opensearch import create_indexer_client, INDEX_NAME

router = APIRouter(prefix="/api/v1")

indexer_client = create_indexer_client()


@router.post("/login")
async def login(login: Login):
    try:
        data = indexer_client.get(index=INDEX_NAME, id=login.uuid)
    except opensearchpy.exceptions.NotFoundError:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": "UUID not found"})
        
    if not compare_digest(data["_source"]["key"], login.key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "Invalid key"})

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
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, {"message": "No commands found"})
