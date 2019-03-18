# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util


class Cluster(Model):

    def __init__(self, content: str =''):
        """Cluster body model
        :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of a command name
        :type command: str
        :param custom: Whether the specified command is a custom command or not
        :type custom: bool
        :param arguments: Command arguments
        :type arguments: str
        """
        self.swagger_types = {
            'content': str
        }

        self.attribute_map = {
            'content': 'content'
        }

        self._content = content

    @classmethod
    def from_dict(cls, dikt) -> Dict:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The Agent of this Agent.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def content(self) -> str:
        """
        :return: Content of the file
        :rtype: str
        """
        return self._content

    @content.setter
    def content(self, content):
        """Content of the file
        :param content: Content of the file
        """
        self._content = content
