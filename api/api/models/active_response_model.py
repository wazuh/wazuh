# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util


class ActiveResponse(Model):

    def __init__(self, command='', custom=False, arguments=''):
        """ActiveResponse body model

        :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of a command name
        :type command: str
        :param custom: Whether the specified command is a custom command or not
        :type custom: bool
        :param arguments: Command arguments
        :type arguments: str
        """
        self.swagger_types = {
            'command': str,
            'custom': bool,
            'arguments': str
        }

        self.attribute_map = {
            'command': 'command',
            'custom': 'custom',
            'arguments': 'arguments'
        }

        self._command = command
        self._custom = custom
        self._arguments = arguments

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
    def command(self) -> str:
        """
        :return: Command to run in the agent
        :rtype: str
        """
        return self._command

    @command.setter
    def command(self, command):
        """Command running in the agent.

        :param command: Command to run in the agent
        """
        self._command = command

    @property
    def custom(self) -> str:
        """
        :return: Whether the specified command is a custom command or not
        :rtype: bool
        """
        return self._custom

    @custom.setter
    def custom(self, custom):
        """
        :param command: Whether the specified command is a custom command or not
        """
        self._custom = custom

    @property
    def arguments(self) -> str:
        """
        :return: Command arguments
        :rtype: str
        """
        return self._command

    @arguments.setter
    def arguments(self, arguments):
        """Command running in the agent.

        :param arguments: Command arguments
        """
        self._arguments = arguments