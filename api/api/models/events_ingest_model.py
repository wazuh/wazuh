from api.models.base_model_ import Body


class EventsIngestModel(Body):
    def __init__(self, events: list) -> None:
        self.swagger_types = {
            'events': list,
        }

        self.attribute_map = {
            'events': 'events',
        }

        self._events = events

    @property
    def events(self) -> list:
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
