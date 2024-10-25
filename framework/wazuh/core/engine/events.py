from dataclasses import asdict
from httpx import RequestError
from typing import List

from wazuh.core.engine.base import APPLICATION_JSON, BaseModule
from wazuh.core.engine.models.base import ErrorResponse
from wazuh.core.engine.models.events import StatelessEvent
from wazuh.core.exception import WazuhEngineError


class EventsModule(BaseModule):
    """Events module to send stateless events to the Engine."""

    MODULE = 'events'

    async def send(self, events: List[StatelessEvent]) -> None:
        """Send events to the engine.
        
        Parameters
        ----------
        events : List[StatelessEvent]
            Events list.
        """
        try:
            for event in events:
                response = await self._client.post(
                    url=f'{self.API_URL}/{self.MODULE}/stateless',
                    json=asdict(event),
                    headers={
                        'Accept': APPLICATION_JSON,
                        'Content-Type': APPLICATION_JSON,
                    }
                )

                if response.status_code != 200:
                    return ErrorResponse(**response.json())

        except RequestError as exc:
            raise WazuhEngineError(2803, extra_message=str(exc))
