from typing import List, Optional

from connexion import ProblemException

from api.models.base_model_ import Body

MAX_EVENTS_PER_REQUEST = 100


class EventsIngestModel(Body):

    def __init__(self, events: Optional[list] = None) -> None:
        """EventsIngestModel body model.

        Parameters
        ----------
        events : Optional[list], optional
            List of events, by default None.
        """
        self.swagger_types = {
            'events': List[str],
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
        if len(events) > MAX_EVENTS_PER_REQUEST:
            raise ProblemException(
                status=400,
                title='Events bulk size exceeded',
                detail='The size of the events bulk is exceeding the limit'
            )

        self._events = events
