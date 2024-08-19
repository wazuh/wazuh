from typing import List

from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.events import StatelessEvent


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
        # TODO(25121): Send events to the engine once the API endpoint is available.
