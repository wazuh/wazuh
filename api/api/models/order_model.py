# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import List

from api.models.base_model_ import Body, Model


class Action(Model):
    """Order action model."""

    def __init__(self, name: str = None, args: List[str] = None, version: str = None):
        self.swagger_types = {'name': str, 'args': List[str], 'version': str}

        self.attribute_map = {'name': 'name', 'args': 'args', 'version': 'version'}

        self._name = name
        self._args = args
        self._version = version

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def args(self) -> List[str]:
        return self._args

    @args.setter
    def args(self, args: List[str]):
        self._args = args

    @property
    def version(self) -> str:
        return self._version

    @version.setter
    def version(self, version: str):
        self._version = version


class Target(Model):
    """Order target model."""

    def __init__(self, id: str = None, type: str = None):
        self.swagger_types = {'id': str, 'type': str}

        self.attribute_map = {'id': 'id', 'type': 'type'}

        self._id = id
        self._type = type

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, id: str):
        self._id = id

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type


class Order(Model):
    """Order body model."""

    def __init__(
        self,
        source: str = None,
        user: str = None,
        target: Target = None,
        action: Action = None,
        document_id: str = None,
    ):
        self.swagger_types = {
            'source': str,
            'user': str,
            'target': Target,
            'action': Action,
            'document_id': str,
        }

        self.attribute_map = {
            'source': 'source',
            'user': 'user',
            'target': 'target',
            'action': 'action',
            'document_id': 'document_id',
        }

        self._source = source
        self._user = user
        self._target = target
        self._action = action
        self._document_id = document_id

    @property
    def source(self) -> str:
        return self._source

    @source.setter
    def source(self, source: str):
        self._source = source

    @property
    def user(self) -> str:
        return self._user

    @user.setter
    def user(self, user: str):
        self._user = user

    @property
    def target(self) -> Target:
        return self._target

    @target.setter
    def target(self, target: Target):
        self._target = target

    @property
    def action(self) -> Action:
        return self._action

    @action.setter
    def action(self, action: Action):
        self._action = action

    @property
    def document_id(self) -> str:
        return self._document_id

    @document_id.setter
    def document_id(self, document_id: str):
        self._document_id = document_id


class Orders(Body):
    """Orders body model."""

    def __init__(self, orders: List[Order] = None) -> None:
        self.swagger_types = {
            'orders': List[Order],
        }

        self.attribute_map = {
            'orders': 'orders',
        }

        self._orders = orders

    @property
    def orders(self) -> List[Order]:
        return self._orders

    @orders.setter
    def orders(self, orders: List[Order]) -> None:
        self._orders = orders
