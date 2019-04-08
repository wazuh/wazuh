# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from copy import deepcopy
from numbers import Number

from wazuh import utils
from wazuh.common import database_limit
from wazuh.exception import WazuhException, WazuhInternalError


class WazuhResult(dict):

    def __init__(self, dct, str_priority=None):
        super().__init__(dct)
        self._str_priority = str_priority

    def __or__(self, other):
        
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
                    priorities = self._str_priority + result[key] + field
                    result[key] = result[key] if priorities.index(result[key]) < priorities.index(field) else field
                else:
                    result[key] = "|".join([result[key], field]) if result[key] != field else field

        return result

    def to_dict(self):
        return {
            'str_priority': self._str_priority,
            'result': deepcopy(self)
        }

    def limit(self, limit=database_limit, offset=0):
        return deepcopy(self)

    def sort(self, fields=[], order='asc'):
        return deepcopy(self)

    @classmethod
    def from_dict(cls, dct):
        result = cls(dct['result'], str_priority=dct['str_priority'])
        result.update(dct['result'])
        return result


class WazuhQueryResult(WazuhResult):

    def limit(self, limit=database_limit, offset=0):
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = result['data']['items'][offset:offset+limit]
        return result

    def sort(self, fields=[], order='asc'):
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = utils.sort_array(result['data']['items'], fields, order)
        return result
