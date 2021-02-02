# coding: utf-8

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body


class ActiveResponseModel(Body):

    def __init__(self, command: str = None, custom: bool = None, arguments: List[str] = None, alert: dict = None):
        """ActiveResponseModel body model

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts by !, then it refers to a script name instead of a command name
        custom : bool
            Whether the specified command is a custom command or not
        arguments : List[str]
            Command arguments
        alert : dict
            Alert information depending on the AR executed
        """
        self.swagger_types = {
            'command': str,
            'custom': bool,
            'arguments': List[str],
            'alert': dict
        }

        self.attribute_map = {
            'command': 'command',
            'custom': 'custom',
            'arguments': 'arguments',
            'alert': 'alert'
        }

        self._command = command
        self._custom = custom
        self._arguments = arguments
        self._alert = alert

    @property
    def command(self) -> str:
        """
        Returns
        -------
        command : str
            Command to run in the agent
        """
        return self._command

    @command.setter
    def command(self, command: str):
        """
        Parameters
        ----------
        command : str
            Command to run in the agent
        """
        self._command = command

    @property
    def custom(self) -> bool:
        """
        Returns
        -------
        custom : bool
            Whether the specified command is a custom command or not
        """
        return self._custom

    @custom.setter
    def custom(self, custom: bool):
        """
        Parameters
        ----------
        custom : bool
            Whether the specified command is a custom command or not
        """
        self._custom = custom

    @property
    def arguments(self) -> List[str]:
        """
        Returns
        -------
        arguments : List[str]
            Command arguments
        """
        return self._arguments

    @arguments.setter
    def arguments(self, arguments: List[str]):
        """
        Parameters
        ----------
        arguments : List[str]
            Command arguments
        """
        self._arguments = arguments

    @property
    def alert(self) -> dict:
        """
        Returns
        -------
        alert : dict
            Alert data sent with the AR command
        """
        return self._alert

    @alert.setter
    def alert(self, alert: List[str]):
        """
        Parameters
        ----------
        alert : dict
            Alert data sent with the AR command
        """
        self._alert = alert
