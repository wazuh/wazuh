import asyncio
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, Response
from hmac import compare_digest
import json
import opensearchpy
import os
from typing import Annotated, List

from auth import JWTBearer, generate_token, decode_token
from models import Command, Credentials, GetCommandsResponse, EventsBody, TokenResponse
from opensearch import create_indexer_client, INDEX_NAME
from redis_client import create_redis_client

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

router = APIRouter(prefix="/api/v1")
indexer_client = create_indexer_client()
redis_cli = create_redis_client()
timeout = 60


async def fetch_commands(uuid: str) -> List[Command]:
    for _ in range(timeout):
        length = redis_cli.llen(uuid)
        if length > 0:
            commands: List[Command] = []

            bulk = redis_cli.pipeline()
            bulk.lrange(uuid, 0, -1)
            bulk.delete(uuid)
            (results, _) = bulk.execute()

            for command in results:
                commands.append(json.loads(command))

            return commands
        else:
            await asyncio.sleep(1)

    return None

@router.get("/commands")
async def get_commands(token: Annotated[str, Depends(JWTBearer())]) -> GetCommandsResponse:
    try:
        uuid = decode_token(token)["uuid"]
    except Exception as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": str(exc)})

    commands = await fetch_commands(uuid)
    if commands:
        return GetCommandsResponse(commands=commands)
    else:
        raise HTTPException(status.HTTP_408_REQUEST_TIMEOUT, {"message": "No commands found"})

@router.get("/files", dependencies=[Depends(JWTBearer())])
async def get_files(file_name: str):
    path = os.path.join(BASE_DIR, "files", file_name)
    return FileResponse(path, media_type="application/octet-stream", filename=file_name)

@router.post("/events/stateless", dependencies=[Depends(JWTBearer())])
async def post_stateless_events(body: EventsBody):
    # TODO: send event to the engine
    _ = body.events
    return Response(status_code=status.HTTP_200_OK)

@router.post("/events/stateful", dependencies=[Depends(JWTBearer())])
async def post_stateful_events(body: EventsBody):
    # TODO: send event to the indexer
    _ = body.events
    return Response(status_code=status.HTTP_200_OK)

@router.post("/authentication")
async def authentication(creds: Credentials):
    try:
        data = indexer_client.get(index=INDEX_NAME, id=creds.uuid)
    except opensearchpy.exceptions.NotFoundError:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": "UUID not found"})
    except opensearchpy.exceptions.ConnectionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": f"Couldn't connect to the indexer: {exc}"})

    if not compare_digest(data["_source"]["key"], creds.key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "Invalid Key"})

    token = generate_token(creds.uuid)
    return TokenResponse(token=token)
