from typing import Any
from api.models.base_model_ import Body, Model


class DbEntryModel(Body):
    def __init__(self, name: str, value: Any, key: str):
        self.swagger_types = {
            'name': str,
            'value': dict,
            'key': str
        }

        self.attribute_map = {
            'name': name,
            'value': value,
            'key': key
        }

        self._name = name
        self._value = value
        self._key = key

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def value(self) -> Any:
        return self._value

    @value.setter
    def value(self, value: Any):
        self._value = value

    @property
    def key(self) -> str:
        return self._key

    @key.setter
    def key(self, key: str):
        self._key = key


class DbCreationModel(Body):
    def __int__(self, name: str, path: str):
        self.swagger_types = {
            'name': str,
            'path': str
        }

        self.attribute_map = {
            'name': name,
            'path': path
        }

        self._name = name
        self._path = path

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, path: str):
        self._path = path
