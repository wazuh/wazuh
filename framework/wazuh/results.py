# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from copy import deepcopy
from numbers import Number

from wazuh import utils
from wazuh.common import database_limit
from wazuh.exception import WazuhException, WazuhInternalError


class WazuhResult(dict):
    """
    Models a result returned by any framework function. This should be the class of object that every
    framework function returns.
    """

    def __init__(self, dct, str_priority=None):
        """
        Initializes an instance

        :param dct: map to take key-values from
        :param str_priority: list of strings. If not None, conflicts when merging str values in the result
         are solved taking the first value found in str_priority. I.e.: {'foo': 'KO'} and {'foo': 'OK'} results in
         {'foo': 'KO'} if str_priority is set to ['KO', 'OK'] because 'KO' takes a higher priority level than 'OK'
        """
        super().__init__(dct)
        self._str_priority = str_priority

    def __or__(self, other):
        """
        | operator used to merge two WazuhResult objects. When merged with a WazuhException, the result is always a
        WazuhException
        :param other: WazuhResult or WazuhException
        :return: a new WazuhResult or WazuhException
        """
        if isinstance(other, WazuhException):
            return other
        elif not isinstance(other, dict):
            raise WazuhInternalError(1000, extra_message=f"WazuhResult cannot be merged with {type(other)} object")

        result = deepcopy(self)

        for key, field in other.items():
            if key not in result:
                result[key] = field
            elif isinstance(field, dict):
                result[key] = WazuhResult(result[key]) | WazuhResult(field)
            elif isinstance(field, list):
                self_field = result[key]
                result[key] = [*self_field, *[elem for elem in field if elem not in self_field]]
            elif isinstance(field, Number):
                result[key] = result[key] + field
            elif isinstance(field, str):  # str
                if self._str_priority is not None:
                    priorities = str(self._str_priority) + str(result[key]) + str(field)
                    result[key] = result[key] if priorities.index(result[key]) < priorities.index(field) else field
                else:
                    result[key] = "|".join([result[key], field]) if result[key] != field else field

        return result

    def to_dict(self):
        """
        Translates the result into a dict
        :return: dict
        """
        return {
            'str_priority': self._str_priority,
            'result': deepcopy(self)
        }

    def limit(self, limit=database_limit, offset=0):
        """
        Should take the first `limit` results starting from `offset`

        To be redefined in WazuhResult subclasses.

        :param limit: integer. Default the value specified in wazuh.common.database_limit
        :param offset: integer. Default 0.
        :return: filtered WazuhResult
        """
        return deepcopy(self)

    def sort(self, fields=None, order='asc'):
        """
        Sorts according to `fields` in order `order`

        To be redefined in WazuhResult subclasses.

        :param fields: criteria for sorting the results
        :param order: string. Must be 'asc' or 'desc'
        :return: sorted WazuhResult
        """
        return deepcopy(self)

    @classmethod
    def from_dict(cls, dct):
        """
        Builds an instance from a dict
        :param dct: dict
        :return: instance of cls
        """
        result = cls(dct['result'], str_priority=dct['str_priority'])
        result.update(dct['result'])
        return result


class WazuhQueryResult(WazuhResult):
    """
    Result that implements limit and sort methods.

    Should be used for results with a data.items structure
    """

    def limit(self, limit=database_limit, offset=0):
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = result['data']['items'][offset:offset+limit]
        return result

    def sort(self, fields=None, order='asc'):
        fields = [] if fields is None else fields
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = utils.sort_array(result['data']['items'], fields, order)
        return result
