from typing import List

from pydantic import BaseModel

from wazuh.core.engine.models.events import StatelessEvent


class StatelessEvents(BaseModel):
    events: List[StatelessEvent]
