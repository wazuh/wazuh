from asyncio import sleep
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from typing import Annotated, Dict, List

from auth import JWTBearer, generate_token, decode_token
from models import Command, PostCommandsBody, PostEventsBody, Login

app = FastAPI()
router = APIRouter(prefix="/api/v1")
timeout = 60

class CommandsManager:
    __commands: Dict[str, List[str]] = {}

    def add_commands(self, uuid: str, commands: List[Command]) -> None:
        if uuid in self.__commands:
            self.__commands[uuid].extend(commands)
        else:
            self.__commands[uuid] = commands

    async def get_commands(self, uuid: str) -> List[Command]:
        for i in range(timeout):
            if len(self.__commands[uuid]) > 0:
                # TODO: these operations should be atomic and thread-safe
                commands = self.__commands[uuid][:]
                self.__commands[uuid][:] = []
                return commands
            else:
                await sleep(1)

        return None

commands_manager = CommandsManager()

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

@router.post("/commands")
async def post_commands(body: PostCommandsBody, token: Annotated[str, Depends(JWTBearer(check_send_commands=True))]):
    decoded_token = decode_token(token)
    commands_manager.add_commands(decoded_token["uuid"], body.commands)
    return {"message": "Commands added"}


app.include_router(router)
