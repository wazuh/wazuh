# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List
from api.models.base_model_ import Body

class IntegrationCreateModel(Body):
    """
    IntegrationCreateModel body model.

    Parameters
    ----------
    type : str
        Integration type.
    name : str
        Integration name.
    id : str
        Integration ID.
    description : str
        Integration description.
    documentation : str
        Integration documentation.
    status : str
        Integration status.
    kvdbs : List[str]
        List of KVDBs associated with the integration.
    decoders : List[str]
        List of decoders associated with the integration.
    """
    def __init__(self, type: str = '', name: str = '', id: str = '', description: str = '', documentation: str = '', status: str = '',
                 kvdbs: List[str] = None, decoders: List[str] = None):
        self.swagger_types = {
            'type': str,
            'name': str,
            'id': str,
            'description': str,
            'documentation': str,
            'status': str,
            'kvdbs': List[str],
            'decoders': List[str]
        }

        self.attribute_map = {
            'type': 'type',
            'name': 'name',
            'id': 'id',
            'description': 'description',
            'documentation': 'documentation',
            'status': 'status',
            'kvdbs': 'kvdbs',
            'decoders': 'decoders'
        }

        self._type = type
        self._name = name
        self._id = id
        self._description = description
        self._documentation = documentation
        self._status = status
        self._kvdbs = kvdbs or []
        self._decoders = decoders or []

    # --- properties ---

    @property
    def type(self) -> str:
        """Integration type getter.

        Returns
        -------
        type : str
            Integration type.
        """
        return self._type

    @type.setter
    def type(self, value: str):
        """Integration type setter.

        Parameters
        ----------
        value : str
            Integration type.
        """
        self._type = value

    @property
    def name(self) -> str:
        """Integration name getter.

        Returns
        -------
        name : str
            Integration name.
        """
        return self._name

    @name.setter
    def name(self, value: str):
        """Integration name setter.

        Parameters
        ----------
        value : str
            Integration name.
        """
        self._name = value

    @property
    def id(self) -> str:
        """Integration ID getter.

        Returns
        -------
        id : str
            Integration ID.
        """
        return self._id

    @id.setter
    def id(self, value: str):
        """Integration ID setter.

        Parameters
        ----------
        value : str
            Integration ID.
        """
        self._id = value

    @property
    def description(self) -> str:
        """Integration description getter.

        Returns
        -------
        description : str
            Integration description.
        """
        return self._description

    @description.setter
    def description(self, value: str):
        """Integration description setter.

        Parameters
        ----------
        value : str
            Integration description.
        """
        self._description = value

    @property
    def documentation(self) -> str:
        """Integration documentation getter.

        Returns
        -------
        documentation : str
            Integration documentation.
        """
        return self._documentation

    @documentation.setter
    def documentation(self, value: str):
        """Integration documentation setter.

        Parameters
        ----------
        value : str
            Integration documentation.
        """
        self._documentation = value

    @property
    def status(self) -> str:
        """Integration status getter.

        Returns
        -------
        status : str
            Integration status.
        """
        return self._status

    @status.setter
    def status(self, value: str):
        """Integration status setter.

        Parameters
        ----------
        value : str
            Integration status.
        """
        self._status = value

    @property
    def kvdbs(self) -> List[str]:
        """KVDBs getter.

        Returns
        -------
        kvdbs : List[str]
            List of KVDBs associated with the integration.
        """
        return self._kvdbs

    @kvdbs.setter
    def kvdbs(self, value: List[str]):
        """KVDBs setter.

        Parameters
        ----------
        value : List[str]
            List of KVDBs associated with the integration.
        """
        self._kvdbs = value

    @property
    def decoders(self) -> List[str]:
        """Decoders getter.

        Returns
        -------
        decoders : List[str]
            List of decoders associated with the integration.
        """
        return self._decoders

    @decoders.setter
    def decoders(self, value: List[str]):
        """Decoders setter.

        Parameters
        ----------
        value : List[str]
            List of decoders associated with the integration.
        """
        self._decoders = value
