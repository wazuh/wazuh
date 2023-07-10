from api.models.base_model_ import Body, Model


class RouteUpdateModel(Body):
    def __init__(self, name: str, priority: int):
        self.swagger_types = {
            'name': str,
            'priority': int
        }

        self.attribute_map = {
            'name': 'name',
            'priority': 'priority'
        }

        self._name = name
        self._priority = priority

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def priority(self) -> int:
        return self._priority

    @priority.setter
    def priority(self, priority: int):
        self._priority = priority


class RouteCreateModel(Body):
    def __init__(self, name: str, policy: str, filter: str, priority: int):
        self.swagger_types = {
            'name': str,
            'policy': str,
            'filter': str,
            'priority': int
        }

        self.attribute_map = {
            'name': 'name',
            'filter': 'filter',
            'policy': 'policy',
            'priority': 'priority'
        }

        self._name = name
        self._policy = policy
        self._filter = filter
        self._priority = priority

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def policy(self) -> str:
        return self._policy

    @policy.setter
    def policy(self, policy: str):
        self._policy = policy

    @property
    def filter(self) -> str:
        return self._filter

    @filter.setter
    def filter(self, filter: str):
        self._filter = filter

    @property
    def priority(self) -> int:
        return self._priority

    @priority.setter
    def priority(self, priority: int):
        self._priority = priority
