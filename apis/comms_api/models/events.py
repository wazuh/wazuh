from typing import List

from pydantic import BaseModel

from wazuh.core.engine.models.events import StatelessEvent
from wazuh.core.indexer.models.events import StatefulEvent


class StatefulEvents(BaseModel):
    events: List[StatefulEvent]


class StatelessEvents(BaseModel):
    events: List[StatelessEvent]
