from typing import Optional, List, Dict

from api.models.base_model_ import Body


class EventsIngestModel(Body):

    def __init__(self, events: Optional[list] = None) -> None:
        self.swagger_types = {
            'events': List[dict],
        }

        self.attribute_map = {
            'events': 'events',
        }

        self._events = events

    @property
    def events(self) -> Optional[list]:
        """
        :return: Events list
        :rtype: list
        """
        return self._events

    @events.setter
    def events(self, events: list) -> None:
        """
        :param events: Events list
        """
        self._events = events
