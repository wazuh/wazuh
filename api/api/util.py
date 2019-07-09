
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import functools
import os
import typing
from functools import wraps

import six
from connexion import problem
from flask import current_app

from wazuh.common import ossec_path as WAZUH_PATH
from wazuh.exception import WazuhException, WazuhInternalError, WazuhError
import wazuh.results as wresults


def serialize(item):
    try:
        if isinstance(item, datetime.datetime):
            return item.replace(tzinfo=datetime.timezone.utc).isoformat(sep='T', timespec='seconds')
        else:
            return item
    except Exception:
        return item


def _deserialize(data, klass):
    """Deserializes dict, list, str into an object.

    :param data: dict, list or str.
    :param klass: class literal, or string of class name.

    :return: object.
    """
    if data is None:
        return None

    if klass in six.integer_types or klass in (float, str, bool):
        return _deserialize_primitive(data, klass)
    elif klass == object:
        return _deserialize_object(data)
    elif klass == datetime.date:
        return deserialize_date(data)
    elif klass == datetime.datetime:
        return deserialize_datetime(data)
    elif hasattr(klass, '__origin__'):
        if klass.__origin__ == list:
            return _deserialize_list(data, klass.__args__[0])
        if klass.__origin__ == dict:
            return _deserialize_dict(data, klass.__args__[1])
    else:
        return deserialize_model(data, klass)


def _deserialize_primitive(data, klass):
    """Deserializes to primitive type.

    :param data: data to deserialize.
    :param klass: class literal.

    :return: int, long, float, str, bool.
    :rtype: int | long | float | str | bool
    """
    try:
        value = klass(data)
    except UnicodeEncodeError:
        value = six.u(data)
    except TypeError:
        value = data
    return value


def _deserialize_object(value):
    """Return a original value.

    :return: object.
    """
    return value


def deserialize_date(string):
    """Deserializes string to date.

    :param string: str.
    :type string: str
    :return: date.
    :rtype: date
    """
    try:
        from dateutil.parser import parse
        return parse(string).date()
    except ImportError:
        return string


def deserialize_datetime(string):
    """Deserializes string to datetime.

    The string should be in iso8601 datetime format.

    :param string: str.
    :type string: str
    :return: datetime.
    :rtype: datetime
    """
    try:
        from dateutil.parser import parse
        return parse(string)
    except ImportError:
        return string


def deserialize_model(data, klass):
    """Deserializes list or dict to model.

    :param data: dict, list.
    :type data: dict | list
    :param klass: class literal.
    :return: model object.
    """
    instance = klass()

    if not instance.swagger_types:
        return data

    for attr, attr_type in six.iteritems(instance.swagger_types):
        if data is not None \
                and instance.attribute_map[attr] in data \
                and isinstance(data, (list, dict)):
            value = data[instance.attribute_map[attr]]
            setattr(instance, attr, _deserialize(value, attr_type))

    return instance


def _deserialize_list(data, boxed_type):
    """Deserializes a list and its elements.

    :param data: list to deserialize.
    :type data: list
    :param boxed_type: class literal.

    :return: deserialized list.
    :rtype: list
    """
    return [_deserialize(sub_data, boxed_type)
            for sub_data in data]


def _deserialize_dict(data, boxed_type):
    """Deserializes a dict and its elements.

    :param data: dict to deserialize.
    :type data: dict
    :param boxed_type: class literal.

    :return: deserialized dict.
    :rtype: dict
    """
    return {k: _deserialize(v, boxed_type)
            for k, v in six.iteritems(data)}


def remove_nones_to_dict(dct):
    """Removes none values from a dict recursively

    :param dct: dict to filter
    :return: new dict without none values
    """
    return {k: v if not isinstance(v, dict) else remove_nones_to_dict(v)
            for k, v in dct.items() if v is not None}


def parse_api_param(param: str, param_type: str) -> [typing.Dict, None]:
    """Parses an str parameter from the API query and returns a dictionary the framework can process

    :param param: Str parameter coming from the API.
    :param param_type: Type of parameter -> search or sort
    :return: A dictionary
    """
    if param is not None:
        my_func = f'_parse_{param_type}_param'
        parser = globals().get(my_func, lambda x: x)
        return parser(param)
    else:
        return param


def _parse_search_param(search: str) -> typing.Dict:
    """Parses search str param coming from the API query into a dictionary the framework can process.

    :param search: Search parameter coming from the API query
    :return: A dictionary like {'value': 'ubuntu', 'negation': False}
    """
    negation = search[0] == '-'
    return {'negation': negation, 'value': search[1:] if negation else search}


def _parse_sort_param(sort: str) -> [typing.Dict, None]:
    """Parses sort str param coming from the API query into a dictionary the framework can process.

    :param sort: Sort parameter coming from the API query
    :return: A dictionary like {"fields":["field1", "field1"], "order": "desc"}
    """
    sort_fields = sort[(1 if sort[0] == '-' or sort[0] == '+' else 0):]
    return {'fields': sort_fields.split(','), 'order': 'desc' if sort[0] == '-' else 'asc'}


def to_relative_path(full_path):
    """Returns a relative path from Wazuh base directory

    :param full_path: Full path
    :type path: str
    :return: Relative path
    :rtype: str
    """
    return os.path.relpath(full_path, WAZUH_PATH)


def flask_cached(f):
    """Adds a cache handler decorator to the function
    This method is used to avoid problems accessing API app from API controllers without an existing app_context

    :param f: function to decorate
    :return: decorated function
    """
    @functools.wraps(f)
    def cached_function(*args, **kwargs):

        @current_app.cache.memoize()
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function(*args, **kwargs)

    return cached_function


def _create_problem(exc):
    """
    Builds an HTTP response to show a WazuhException information
    :param exc: WazuhException to be rendered
    :return: HTTP response to be return by an API controller
    """
    if isinstance(exc, WazuhException):
        ext = remove_nones_to_dict({'remediation': exc.remediation,
                                    'code': exc.code,
                                    'dapi_errors': exc.dapi_errors
                                    })
    else:
        ext = None
    if isinstance(exc, WazuhError):
        return problem(400,
                       'Wazuh Error',
                       exc.message,
                       ext=ext)
    elif isinstance(exc, (WazuhInternalError, WazuhException)):
        return problem(500,
                       'Wazuh Internal Error',
                       exc.message,
                       ext=ext)
    raise exc


def exception_handler(f):
    """
    Enables a controller to handle a WazuhException return by a framework function

    Intended to be used as a decorator
    """
    @wraps(f)
    def handle_exception(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            if isinstance(result, tuple) or isinstance(result, list):
                if len(result) > 0:
                    if isinstance(result[0], Exception):
                        raise result[0]
            return result
        except Exception as e:
            return _create_problem(e)

    return handle_exception


def parse_api_param(param: str, param_type: str) -> [typing.Dict, None]:
    """
    Parses an str parameter from the API query and returns a dictionary the framework can process

    :param param: Str parameter coming from the API.
    :param param_type: Type of parameter -> search or sort
    :return: A dictionary
    """
    if param is not None:
        my_func = f'_parse_{param_type}_param'
        parser = globals().get(my_func, lambda x: x)
        return parser(param)
    else:
        return param


def _parse_search_param(search: str) -> typing.Dict:
    """
    Parses search str param coming from the API query into a dictionary the framework can process.

    :param search: Search parameter coming from the API query
    :return: A dictionary like {'value': 'ubuntu', 'negation': False}
    """
    negation = search[0] == '-'
    return {'negation': negation, 'value': search[1:] if negation else search}


def _parse_sort_param(sort: str) -> [typing.Dict, None]:
    """
    Parses sort str param coming from the API query into a dictionary the framework can process.

    :param sort: Sort parameter coming from the API query
    :return: A dictionary like {"fields":["field1", "field1"], "order": "desc"}
    """
    sort_fields = sort[(1 if sort[0] == '-' or sort[0] == ' ' else 0):]
    return {'fields': sort_fields.split(','), 'order': 'desc' if sort[0] == '-' else 'asc'}


def raise_if_exc(obj):
    """
    Checks if obj is an Exception a raises it. Otherwise it is returned

    :param obj: object to be checked
    :return: obj only if it is not an Exception instance
    """
    if isinstance(obj, Exception):
        raise obj
    else:
        return obj
