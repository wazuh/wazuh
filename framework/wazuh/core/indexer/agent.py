from opensearchpy import exceptions
from uuid6 import uuid7
from wazuh.core.exception import WazuhError, WazuhResourceNotFound

from .base import BaseIndex
from .models import Agent

NAME_KEY = 'name'
PASSWORD_KEY = 'password'
SOURCE_KEY = '_source'


class AgentsListIndex(BaseIndex):
    """Set of methods to interact with `agents_list` index."""

    INDEX = 'agents_list'

    async def add(self, uuid: uuid7, password: str, name: str) -> Agent:
        try:
            self._client.index(
                index=self.INDEX,
                id=uuid,
                body={'name': name, 'password': password},
                op_type='create',
            )
        except exceptions.ConflictError:
            raise WazuhError(1708, extra_message=uuid)
        finally:
            return Agent(uuid=uuid, password=password, name=name)

    async def get(self, uuid: uuid7) -> Agent:
        try:
            data = self._client.get(index=self.INDEX, id=self.uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)
        finally:
            return Agent(uuid=uuid, **data[SOURCE_KEY])

    async def delete(self, uuid: uuid7):
        try:
            self._client.delete(id=uuid)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(1701)
