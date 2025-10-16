# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List
from api.models.base_model_ import Body, Model

class IntegrationInfoModel(Body):
    """
    IntegrationInfo model.

    Parameters
    ----------
    id : str
        Integration ID.
    name : str
        Integration name.
    """
    def __init__(self, id: str = '', name: str = ''):
        self.swagger_types = {
            'id': str,
            'name': str
        }
        self.attribute_map = {
            'id': 'id',
            'name': 'name'
        }
        self._id = id
        self._name = name

    # --- properties ---

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

class IntegrationsOrderModel(Body):
    """
    IntegrationsOrder body model.

    Parameters
    ----------
    order : List[IntegrationInfo]
        List of IntegrationInfo objects representing the order.
    """
    def __init__(self, order: List[IntegrationInfoModel] = None):
        self.swagger_types = {
            'order': List[IntegrationInfoModel]
        }
        self.attribute_map = {
            'order': 'order'
        }
        self._order = order or []

    # --- properties ---

    @property
    def order(self) -> List[IntegrationInfoModel]:
        """Order getter.

        Returns
        -------
        order : List[IntegrationInfo]
            List of IntegrationInfo objects representing the order.
        """
        return self._order

    @order.setter
    def order(self, value: List[IntegrationInfoModel]):
        """Order setter.

        Parameters
        ----------
        value : List[IntegrationInfo]
            List of IntegrationInfo objects representing the order.
        """
        self._order = value
