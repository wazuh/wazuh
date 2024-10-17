from typing import List

from pydantic import BaseModel

from wazuh.core.indexer.models.commands import Command, Result


class Commands(BaseModel):
    commands: List[Command]


class CommandsResults(BaseModel):
    results: List[Result]
