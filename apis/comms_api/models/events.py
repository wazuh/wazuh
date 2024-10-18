from typing import List

from pydantic import BaseModel

from wazuh.core.engine.models.events import StatelessEvent
from wazuh.core.indexer.models.events import StatefulEvent, TaskResult


class StatefulEvents(BaseModel):
    events: List[StatefulEvent]


class StatefulEventsResponse(BaseModel):
    results: List[TaskResult]


class StatelessEvents(BaseModel):
    events: List[StatelessEvent]
