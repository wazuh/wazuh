# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import builtins
import collections
import re
import sys
from copy import deepcopy
from numbers import Number

import wazuh.core.exception as wexception
from wazuh.core import utils
from wazuh.core.common import database_limit

current_module = sys.modules[__name__]


class AbstractWazuhResult(collections.abc.MutableMapping):
    """
    Models a result returned by any framework function. This should be the class of object that every
    framework function returns.
    """
    def __init__(self, dct):
        """
        Initializes an instance

        :param dct: map to take key-values from
        """
        if isinstance(dct, dict):
            self.dikt = dct
        elif isinstance(dct, AbstractWazuhResult):
            self.dikt = dct.dikt
        else:
            raise wexception.WazuhInternalError(1000, extra_message=f"dct param must be a dict or "
                                                                    f"an AbstractWazuhResult subclass, "
                                                                    f"not a {type(dct)}")

    def __getitem__(self, item):
        return self.dikt[item]

    def __setitem__(self, key, value):
        self.dikt[key] = value

    def __repr__(self):
        return self.__class__.__name__ + "(" + repr(self.__dict__) + ")"

    def __iter__(self):
        return self.dikt.__iter__()

    def __len__(self):
        return len(self.dikt)

    def __delitem__(self, key):
        del self.dikt[key]

    def __deepcopy__(self, memodict=None):
        obj = type(self)(self.__dict__)
        obj.__dict__.update(self.__dict__)
        return obj

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other

    def __or__(self, other):
        """
        | operator used to merge two AbstractWazuhResult objects. When merged with a WazuhException,
         the result is always a WazuhException
        :param other: AbstractWazuhResult or WazuhException
        :return: a new AbstractWazuhResult or WazuhException
        """
        if isinstance(other, wexception.WazuhException):
            return other
        elif not isinstance(other, (dict, AbstractWazuhResult)):
            raise wexception.WazuhInternalError(1000, extra_message=f"Cannot be merged with {type(other)} object")

        result = deepcopy(self)

        for key, field in other.items():
            if key not in result:
                result[key] = field
            elif isinstance(field, dict):
                result[key] = self._merge_dict(result[key], field, key=key)
            elif isinstance(field, list):
                self_field = result[key]
                result[key] = self._merge_list(self_field, field, key=key)
            elif isinstance(field, Number):
                result[key] = self._merge_number(result[key], field, key=key)
            elif isinstance(field, str):  # str
                result[key] = self._merge_str(result[key], field, key=key)

        return result

    def _merge_dict(self, self_field, other_field, key=None):
        """Merges two dict objects when merging two results recursively converting
        each of them to the specific AbstractWazuhResult subclass
        This method may be redefined in subclasses.

        :param self_field: dict in the left item of the merge
        :param other_field: dict in the right item of the merge
        :param key: name of the key being merged
        :return: dict
        """
        return self.__class__(self_field) | self.__class__(other_field)

    def _merge_list(self, self_field, other_field, key=None):
        """Merges two list objects when merging two results by
        concatenating them.
        This method may be redefined in subclasses.

        :param self_field: list in the left item of the merge
        :param other_field: list in the right item of the merge
        :param key: name of the key being merged
        :return: list
        """
        return [*self_field, *[elem for elem in other_field if elem not in self_field]]

    def _merge_number(self, self_field, other_field, key=None):
        """Merges two numeric objects when merging two results by
        adding them.
        This method may be redefined in subclasses.

        :param self_field: number in the left item of the merge
        :param other_field: number in the right item of the merge
        :param key: name of the key being merged
        :return: number
        """
        return self_field + other_field

    def _merge_str(self, self_field, other_field, key=None):
        """Merges two string objects when merging two results by
        concatenating them using a character '|' as separator.
        This method may be redefined in subclasses.

        :param self_field: string in the left item of the merge
        :param other_field: string in the right item of the merge
        :param key: name of the key being merged
        :return: string
        """
        return "|".join([self_field, other_field]) if self_field != other_field else other_field

    def to_dict(self):
        """
        Translates the result into a dict

        :return: dict
        """
        raise NotImplemented

    def limit(self, limit=database_limit, offset=0):
        """
        Should take the first `limit` results starting from `offset`

        To be redefined in WazuhResult subclasses.

        :param limit: integer. Default the value specified in wazuh.common.database_limit
        :param offset: integer. Default 0.
        :return: filtered AbstractWazuhResult
        """
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = result['data']['items'][offset:offset + limit]
        return result

    def sort(self, fields=None, order='asc'):
        """
        Sorts according to `fields` in order `order`

        To be redefined in WazuhResult subclasses.

        :param fields: criteria for sorting the results
        :param order: string. Must be 'asc' or 'desc'
        :return: sorted AbstractWazuhResult
        """
        fields = [] if fields is None else fields
        result = deepcopy(self)
        if 'data' in result and 'items' in result['data'] and isinstance(result['data']['items'], list):
            result['data']['items'] = utils.sort_array(result['data']['items'], fields, order)
        return result

    def encode_json(self):
        """Translates the result to a serializable dictionary

        :return dict
        """
        return self.to_dict()

    @classmethod
    def decode_json(cls, obj):
        """Converts an encoded dictionary to the original object

        :param obj: dict to be decoded
        :return: a result preserving the original class
        """
        raise NotImplemented

    def render(self):
        """Translates the result to a readable format

        :return: dict
        """
        return self.to_dict()


class WazuhResult(AbstractWazuhResult):
    """
    This class represent a basic framework response. I.e.:
    {"data": "items": [{"item1": "data1"},
                       {"item2": "data2"}
                       ],
     "message": "Everything ok"
     }
    """

    def __init__(self, dct, str_priority=None):
        """
        Initializes an instance

        :param dct: map to take key-values from
        :param str_priority: list of strings. If not None, conflicts when merging str values in the result
         are solved taking the first value found in str_priority. I.e.: {'foo': 'KO'} and {'foo': 'OK'} results in
         {'foo': 'KO'} if str_priority is set to ['KO', 'OK'] because 'KO' takes a higher priority level than 'OK'
        """
        self._str_priority = str_priority
        super().__init__(dct)

    def _merge_str(self, self_field, other_field, key=None):
        if self._str_priority is not None:
            priorities = self._str_priority + [self_field] + [other_field]
            return self_field if priorities.index(self_field) < priorities.index(other_field) else other_field
        else:
            return super()._merge_str(self_field, other_field)

    def to_dict(self):
        """
        Translates the result into a dict

        :return: dict
        """
        return {
            'str_priority': self._str_priority,
            'result': deepcopy(self.dikt)
        }

    @classmethod
    def decode_json(cls, obj):
        """
        Builds an instance from a dict

        :param obj: dict
        :return: instance of cls
        """
        result = cls(obj['result'], str_priority=obj['str_priority'])
        return result

    def render(self):
        self.dikt['error'] = 0
        return self.dikt


class AffectedItemsWazuhResult(AbstractWazuhResult):
    """Models a result in the form:
    {"affected_items": [item1, item2],
     "failed_items": [error1, error2, error3],
     "total_affected_items": 2,
     "total_failed_items": 5,
     ...
     }
    """
    def __init__(self, dikt=None, affected_items=None,
                 total_affected_items=None,
                 sort_fields=None, sort_casting=None, sort_ascending=None,
                 all_msg="", some_msg="", none_msg=""):
        """Initialize method
        :param dikt: dict with result data except affected and failed items
        :param affected_items: list of affected items
        :param total_affected_items: int total number of affected items.
        It may not be the same as length of affected_items
        :param sort_fields: list of strings with the field names to order by. The '.' is the nesting operator for fields
        inside other. Example: 'a.b' -> {'a': {'b': 3}}
        :param sort_casting list of strings. Each item must contain 'str' or 'int'.
        Sets the conversion type to be considered when ordering.
        :param sort_ascending list of booleans. True for ascending, False for descending.
        :param all_msg: str message when all items were successful
        :param some_msg: str message when some items were not successful
        :param none_msg: str message when no items where successful
        """
        dct = {} if dikt is None else dikt
        super().__init__(dct)
        self._affected_items = affected_items if affected_items is not None else []
        self._failed_items = {}
        if total_affected_items is not None:
            self._total_affected_items = total_affected_items
        else:
            self._total_affected_items = len(self._affected_items)
        self._total_failed_items = 0
        self._sort_fields = sort_fields
        self._sort_casting = sort_casting if sort_casting is not None else ['int']
        self._sort_ascending = sort_ascending if sort_ascending is not None else [True]
        self._all_msg = all_msg
        self._some_msg = some_msg
        self._none_msg = none_msg

    def _recalculate_failed_items(self):
        """Updates the failed items count in total_failed_items

        :return: None
        """
        self._total_failed_items = 0
        for ids in self._failed_items.values():
            self._total_failed_items += len(ids)

    def add_failed_item(self, id_=None, error: wexception.WazuhException = None):
        """Adds a new failed item. If the error is the same the id is added properly.

        :param id_: string identifier of the failed item
        :param error: WazuhException instance containing the error description
        :return: None
        """
        # Check if error is already added
        try:
            self._failed_items[error] |= {id_}
        except KeyError:
            self._failed_items[error] = {id_}
        self._recalculate_failed_items()

    def add_failed_items_from(self, other):
        """Adds all failed items from other into the caller object

        :param other: AffectedItemsWazuhResult instance
        :return:
        """
        if not isinstance(other, AffectedItemsWazuhResult):
            raise wexception.WazuhInternalError(1000, extra_message=f"Failed items cannot be taken from {type(other)} object")

        for error, ids in other._failed_items.items():
            for id_ in ids:
                self.add_failed_item(id_=id_, error=error)

    def remove_failed_items(self, code=None):
        """Removes all reference matching the code

        :param code: int WazuhException code
        :return: None
        """
        code = code if code is not None else set()
        self._failed_items = {e: ids for e, ids in self._failed_items.items() if e.code not in code}
        self._recalculate_failed_items()

    def __or__(self, other):
        result = super().__or__(other)
        if isinstance(other, wexception.WazuhError):
            if len(other.ids) > 0:
                for id_ in other.ids:
                    self.add_failed_item(id_=id_, error=other)
                return self
            else:
                return other
        elif isinstance(result, wexception.WazuhException):
            return result
        elif not isinstance(other, AffectedItemsWazuhResult):
            raise wexception.WazuhInternalError(1000, extra_message=f"Cannot be merged with {type(other)} object")

        result.add_failed_items_from(other)
        result.affected_items = merge(result.affected_items,
                                      other.affected_items,
                                      criteria=self.sort_fields,
                                      ascending=self.sort_ascending,
                                      types=self.sort_casting)
        result.total_affected_items = result.total_affected_items + other.total_affected_items

        return result

    def to_dict(self):
        return {
            'affected_items': self.affected_items,
            'failed_items': self.failed_items,
            'sort_fields': self.sort_fields,
            'sort_ascending': self.sort_ascending,
            'sort_casting': self.sort_casting,
            'total_affected_items': self.total_affected_items,
            'total_failed_items': self.total_failed_items,
            'dikt': self.dikt,
            'all_msg': self.all_msg,
            'some_msg': self.some_msg,
            'none_msg': self.none_msg
        }

    @property
    def affected_items(self):
        return self._affected_items

    @affected_items.setter
    def affected_items(self, value):
        self._affected_items = value

    @property
    def sort_fields(self):
        return self._sort_fields

    @sort_fields.setter
    def sort_fields(self, value):
        self._sort_fields = value

    @property
    def sort_casting(self):
        return self._sort_casting

    @sort_casting.setter
    def sort_casting(self, value):
        self._sort_casting = value

    @property
    def sort_ascending(self):
        return self._sort_ascending

    @sort_ascending.setter
    def sort_ascending(self, value):
        self._sort_ascending = value

    @property
    def total_affected_items(self):
        return self._total_affected_items

    @total_affected_items.setter
    def total_affected_items(self, value):
        self._total_affected_items = value

    @property
    def total_failed_items(self):
        return self._total_failed_items

    @property
    def failed_items(self):
        return self._failed_items

    @property
    def all_msg(self):
        return self._all_msg

    @all_msg.setter
    def all_msg(self, value):
        self._all_msg = value

    @property
    def some_msg(self):
        return self._some_msg

    @some_msg.setter
    def some_msg(self, value):
        self._some_msg = value

    @property
    def none_msg(self):
        return self._none_msg

    @none_msg.setter
    def none_msg(self, value):
        self._none_msg = value

    @property
    def message(self):
        if self.total_affected_items == 0:
            return self.none_msg
        else:
            if self.total_failed_items == 0:
                return self.all_msg
            else:
                return self.some_msg

    def _merge_str(self, self_field, other_field, key=None):
        if key == 'older_than':
            return self_field
        else:
            return super()._merge_str(self_field, other_field, key=key)

    @classmethod
    def decode_json(cls, obj):
        result = cls()
        result.affected_items = obj['affected_items']
        result.sort_fields = obj['sort_fields']
        result.sort_casting = obj['sort_casting']
        result.sort_ascending = obj['sort_ascending']
        result.total_affected_items = obj['total_affected_items']
        result.dikt = obj['dikt']
        result.all_msg = obj['all_msg']
        result.some_msg = obj['some_msg']
        result.none_msg = obj['none_msg']

        for exc, set_ in zip(obj['failed_items_keys'], obj['failed_items_values']):
            error = getattr(wexception, exc['__class__']).from_dict(exc['__object__'])
            for id_ in set_:
                result.add_failed_item(id_=id_,
                                       error=error)
        return result

    def encode_json(self):
        result = dict()
        result['affected_items'] = self.affected_items
        result['sort_fields'] = self.sort_fields
        result['sort_casting'] = self.sort_casting
        result['sort_ascending'] = self.sort_ascending
        result['total_affected_items'] = self.total_affected_items
        result['total_failed_items'] = self.total_failed_items
        result['dikt'] = self.dikt
        result['all_msg'] = self.all_msg
        result['some_msg'] = self.some_msg
        result['none_msg'] = self.none_msg
        result['failed_items_keys'] = []
        result['failed_items_values'] = []
        for exc, set_ in self.failed_items.items():
            result['failed_items_keys'].append({'__object__': exc.to_dict(),
                                                '__class__': exc.__class__.__name__
                                                })
            result['failed_items_values'].append(list(set_))

        return result

    def render(self):
        def sort_ids(ids):
            try:
                return sorted(list(ids), key=int)
            except ValueError:
                return sorted(list(ids))

        def set_error_code():
            COMPLETE = 0
            FAILED = 1
            PARTIAL = 2

            if self.total_affected_items > 0 and self.total_failed_items > 0:
                return PARTIAL
            elif self.total_affected_items > 0:
                return COMPLETE
            elif self.total_failed_items > 0:
                return FAILED
            return COMPLETE

        ordered_failed_items = sorted(self.failed_items.items(), key=lambda x: x[0].code)
        result = {
            'affected_items': self.affected_items,
            'total_affected_items': self.total_affected_items,
            'total_failed_items': self.total_failed_items,
            'failed_items': [{'error': {'code': exc.code,
                                        'message': exc.message,
                                        'remediation': exc.remediation
                                        },
                              'id': sort_ids(ids)
                              }
                             for exc, ids in ordered_failed_items],
            **self.dikt
        }

        return {'data': result,
                'message': self.message,
                'error': set_error_code()
                }


def nested_itemgetter(*expressions):
    """Builds a function to get items according to expressions. That getter function receives a dictionary
    as the only positional argument and returns the referenced item.

    Example:
    d = {'a': {'b': 3}, 'c.1': 5}
    items = nested_itemgetter('a.b', 'c\\.1')(d)
    print(items)
    (3, 5)

    :param expressions: one or more strings referencing a value in a dictionary. For nested dictionaries use the '.' as
    the key separator. If the key contains the '.' character escape it using the '\'. If more than one expressions is
    provided a tuple is returned.
    :return: object or tuple of objects
    """
    getters = []
    for expr in expressions:
        fields = re.split(r'(?<!\\)\.', expr)

        def _getter(map_, fields_=tuple(deepcopy(fields))):
            value = map_
            for field in fields_:
                try:
                    value = value[field.replace('\\.', '.')]
                except TypeError:
                    return value
                except KeyError:
                    return None
            return value
        getters.append(_getter)

    def _nested_itemgetter(map_, getters_=tuple(deepcopy(getters))):
        result = [getter(map_) for getter in getters_]
        return result[0] if len(result) == 1 else tuple(result)
    return _nested_itemgetter


def _goes_before_than(a, b, ascending=None, casters=None):
    """Returns true if a should be placed before b according to ascending and casters. It is similar to a
    a lexicographical order but taking into account ascending or descending order in each tuple position.

    :param a: tuple or list
    :param b: tuple or list
    :param ascending: tuple or list of booleans with a length equal to the minimum length between a and b. True if
    ascending, False otherwise.
    :param casters: iterable of callables with a length equal to the minimum length between a and b. The callable
    must fit any class in builtins module (int, str, float, ...). The class will be applied to each value of the
    respective position in a and b before comparing.
    :return: True if a should be placed before b, False otherwise
    """
    if ascending is None:
        ascending = [True] * len(a)
    if casters is None:
        casters = [None] * len(a)
    for item_a, item_b, asc, cast in zip(a, b, ascending, casters):
        if cast is not None:
            item_a = cast(item_a) if item_a is not None else item_a
            item_b = cast(item_b) if item_b is not None else item_b
        if item_a is None:
            return item_b is not None
        elif item_b is None:
            return False
        elif item_a < item_b:
            return asc
        elif item_a > item_b:
            return not asc
    return False


def merge(*iterables, criteria=None, ascending=None, types=None):
    """ Merges iterables in a single one assuming they are already ordered according to criteria, ascending and types

    :param iterables: list of lists to be merged
    :param criteria: list or tuple of expressions accepted by the nested_itemgetter function.
    :param ascending: list or tuple of booleans. Should have the same length as criteria.
    True for ascending False otherwise.
    :param types: list or tuple of strings. Should have the same length as criteria.
    Must fit a class in builtins (int, float, str, ...)
    :return: a new sorted iterable
    """
    result = list()
    final_len = sum([len(iterable) for iterable in iterables])
    if criteria is None:
        getters = [lambda x: x]  # Init dummy itemgetter
    else:
        getters = [nested_itemgetter(criterion) for criterion in criteria]
    casters = [getattr(builtins, type_) for type_ in types]
    while len(result) < final_len:
        selected = None
        for i, iterable in enumerate(iterables):
            if len(iterable) > 0:
                if selected is None:
                    selected = i
                else:
                    candidate = [getter(iterable[0]) for getter in getters]
                    selected_candidate = [getter(iterables[selected][0]) for getter in getters]
                    if _goes_before_than(candidate, selected_candidate, ascending=ascending, casters=casters):
                        selected = i
        result.append(iterables[selected].pop(0))

    return result
