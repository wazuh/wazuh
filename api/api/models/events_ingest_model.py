from typing import List, Optional

from connexion import ProblemException

from api.configuration import api_conf
from api.models.base_model_ import Body

# This value will be defined based on performance. Is bypassed for that reason.
DEFAULT_EVENTS_BULK_MAX_SIZE = 0


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
        bulk_max_size = api_conf.get('events_bulk_max_size', DEFAULT_EVENTS_BULK_MAX_SIZE)
        if bulk_max_size and len(events) > bulk_max_size:
            raise ProblemException(
                status=400,
                title='Events bulk size exceeded',
                detail='The size of the events bulk is exceding the limit'
            )

        self._events = events
