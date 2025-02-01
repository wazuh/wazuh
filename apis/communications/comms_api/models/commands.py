from typing import List

from pydantic import BaseModel

from wazuh.core.indexer.models.commands import Command


class Commands(BaseModel):
    commands: List[Command]
