# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict, Any
from commands import EngineCommand


class EngineRequestBuilder:
    """ Represents a request to the engine"""
    def __init__(self, version: str):
        """
        Initialize the EngineRequestBuilder object.

        Parameters
        ----------
        version : str
            The version of the engine request.
        """
        self.internal_dict: Dict[str, Any] = {"version": version}

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

    def add_parameter(self, key: str, value: Any):
        """
        Add a parameter to the engine request.

        Parameters
        ----------
        key : str
            The key of the parameter.
        value : Any
            The value of the parameter.
        """
        self.internal_dict.setdefault("parameters", {})
        self.internal_dict["parameters"][key] = value

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the EngineRequestBuilder object to a dictionary representation.

        Returns
        -------
        Dict[str, Any]
            The dictionary representation of the EngineRequestBuilder object.
        """
        return self.internal_dict

