from typing import List
from typing_extensions import Self

from pydantic import BaseModel, model_validator

from wazuh.core.indexer.models.commands import Command, Result, Status


class Commands(BaseModel):
    commands: List[Command]


class CommandsResults(BaseModel):
    results: List[Result]

    @model_validator(mode='after')
    def check_status(self) -> Self:
        """Check that the result status is not pending or sent."""
        for result in self.results:
            if result.status not in (Status.SUCCESS, Status.FAILED):
                raise ValueError(f"invalid status, it must be '{Status.SUCCESS}' or '{Status.FAILED}'")

        return self
