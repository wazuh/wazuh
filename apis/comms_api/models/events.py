from typing import List

from pydantic import BaseModel

from wazuh.core.indexer.models.events import AgentMetadata, Header, StatefulEvent, TaskResult


class StatefulEvents(BaseModel):
    agent_metadata: AgentMetadata
    headers: List[Header]
    data: List[StatefulEvent]


class StatefulEventsResponse(BaseModel):
    results: List[TaskResult]
