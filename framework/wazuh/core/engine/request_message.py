# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict, Any, Optional
from wazuh.core.engine.commands import EngineCommand


class EngineRequestMessage:
    """ Represents a request to the engine"""
    def __init__(self, version: int):
        """
        Initialize the EngineRequestBuilder object.

        Parameters
        ----------
        version : str
            The version of the engine request.
        """
        self.internal_dict: Dict[str, Any] = {"version": version}

    def create_message(self, origin_name: str, module: str, command: EngineCommand,
                       parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a message for the engine request.

        Parameters
        ----------
        origin_name : str
            The name of the origin.
        module : str
            The module of the origin.
        command : EngineCommand
            The command for the engine request.
        parameters : Dict[str, Any], optional
            Dictionary with the parameters to add, by default None

        Returns
        -------
        Dict[str, Any]
            The created engine request message.

        """

        self.add_origin(name=origin_name, module=module)
        self.add_command(command=command)

        if parameters:
            self.add_parameters(parameters=parameters)

        return self.to_dict()

    def add_origin(self, name: str, module: str):
        """
        Add the origin details to the engine request.

        Parameters
        ----------
        name : str
            The name of the origin.
        module : str
            The module of the origin.
        """
        self.internal_dict["origin"] = {
            "name": name,
            "module": module
        }

    def add_command(self, command: EngineCommand):
        """
        Add the command to the engine request.

        Parameters
        ----------
        command : EngineCommand
            The command for the engine request.
        """
        self.internal_dict["command"] = command.value

    def add_parameters(self, parameters: Dict[str, Any]):
        """
        Add a parameter to the engine request.

        Parameters
        ----------
        parameters: Dict[str, Any]
            Dictionary with the parameters to add
        """
        self.internal_dict.setdefault("parameters", {})
        self.internal_dict["parameters"].update(parameters)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the EngineRequestBuilder object to a dictionary representation.

        Returns
        -------
        Dict[str, Any]
            The dictionary representation of the EngineRequestBuilder object.
        """
        return self.internal_dict

