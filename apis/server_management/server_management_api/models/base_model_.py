# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pprint
import typing
from json import JSONDecodeError
from typing import Dict, List  # noqa: F401

import six
from connexion import ProblemException
from wazuh.core.exception import WazuhError, WazuhNotAcceptable

from server_management_api import util
from server_management_api.util import get_invalid_keys, raise_if_exc

T = typing.TypeVar('T')


class Model(object):
    # swaggerTypes: The key is attribute name and the
    # value is attribute type.
    swagger_types = {}

    # attributeMap: The key is attribute name and the
    # value is json key in definition.
    attribute_map = {}

    @classmethod
    def from_dict(cls: typing.Type[T], dikt) -> T:
        """Returns the dict as a model."""
        if isinstance(dikt, Exception):
            raise dikt
        return util.deserialize_model(dikt, cls)

    def to_dict(self):
        """Returns the model properties as a dict.

        :rtype: dict
        """
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else util.serialize(item),
                    value.items()
                ))
            else:
                result[attr] = util.serialize(value)

        return result

    def to_str(self):
        """Returns the string representation of the model.

        :rtype: str
        """
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`."""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal."""
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal."""
        return not self == other


class AllOf:

    def __init__(self, *models):
        self.models = models

    def to_dict(self):
        result = {}
        for model in self.models:
            result.update(model.to_dict())
        return result


class Data(Model):

    def __init__(self, data: Model = None):  # noqa: E501
        """Data - a model defined in Swagger.

        :param data: The data of this Data.  # noqa: E501
        :type data: Model
        """
        self.swagger_types = {
            'data': Model
        }

        self.attribute_map = {
            'data': 'data'
        }

        self._data = data

    @classmethod
    def from_dict(cls, dikt) -> 'Data':
        """Returns the dict as a model.

        :param dikt: A dict.
        :type: dict
        :return: The data of this Data.  # noqa: E501
        :rtype: Data
        """
        return util.deserialize_model(dikt, cls)

    @property
    def data(self) -> Model:
        """Gets the data of this Data.


        :return: The data of this Data.
        :rtype: Model
        """
        return self._data

    @data.setter
    def data(self, data: Model):
        """Sets the data of this Data.


        :param data: The data of this Data.
        :type data: Model
        """
        self._data = data


class Items(Model):

    def __init__(self, items: List[Model] = None):  # noqa: E501
        """Items - a model defined in Swagger.

        :param items: The items of this Items.  # noqa: E501
        :type items: Model
        """
        self.swagger_types = {
            'items': List[Model]
        }

        self.attribute_map = {
            'items': 'items'
        }

        self._items = items

    @classmethod
    def from_dict(cls, dikt) -> 'Items':
        """Returns the dict as a model.

        :param dikt: A dict.
        :type: dict
        :return: The Items of this Items.  # noqa: E501
        :rtype: Items
        """
        return util.deserialize_model(dikt, cls)

    @property
    def items(self) -> List[Model]:
        """Gets the items of this Data.


        :return: The items of this Data.
        :rtype: Model
        """
        return self._items

    @items.setter
    def items(self, items: List[Model]):
        """Sets the items of this Items.


        :param items: The items of this Items.
        :type items: Model
        """
        self._items = items


class Body(Model):
    @classmethod
    async def get_kwargs(cls, request, additional_kwargs: dict = None):
        try:
            dikt = request if isinstance(request, dict) else await request.json()
            f_kwargs = util.deserialize_model(dikt, cls).to_dict()
        except JSONDecodeError:
            raise_if_exc(WazuhError(1018))

        if dikt:
            invalid = get_invalid_keys(dikt, f_kwargs)

            if invalid:
                raise ProblemException(status=400, title='Bad Request',
                                       detail=f'Invalid field found {invalid}')

        if additional_kwargs is not None:
            f_kwargs.update(additional_kwargs)

        return f_kwargs

    @classmethod
    def from_dict(cls, dikt):
        """Returns the dict as a model.

        :param dikt: A dict.
        :type: dict
        :return: The Agent of this Agent.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @classmethod
    def decode_body(cls, body, unicode_error=None, attribute_error=None):
        try:
            decoded_body = body.decode('utf-8')
        except UnicodeDecodeError:
            raise_if_exc(WazuhError(unicode_error))
        except AttributeError:
            raise_if_exc(WazuhError(attribute_error))
        return decoded_body

    @classmethod
    def validate_content_type(cls, request, expected_content_type):
        if request.mimetype != expected_content_type:
            raise_if_exc(WazuhNotAcceptable(6002))
