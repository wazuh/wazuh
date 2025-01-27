# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import datetime
import os
import typing
from functools import wraps
from typing import Union

import six
from connexion import ProblemException

from wazuh.core import common, exception
from wazuh.core.cluster.utils import running_in_master_node

logger = logging.getLogger('wazuh-api')


def serialize(item: object) -> object:
    """Serialize item when it is a datetime object.

    Parameters
    ----------
    item : object
        Object to serialize.

    Returns
    -------
    object
        Serialized item.
    """
    try:
        if isinstance(item, datetime.datetime):
            return item.replace(tzinfo=datetime.timezone.utc).isoformat(sep='T', timespec='seconds')
        else:
            return item
    except Exception:
        return item


def _deserialize(data: Union[dict, list, str], klass: type) -> object:
    """Deserialize dict, list, str into an object.

    Parameters
    ----------
    data : dict or list or str
        dict, list or str to deserialize.
    klass : type
        Class literal, or string of class name.

    Returns
    -------
    object
        Deserialized object.
    """
    if data is None:
        return None

    if klass in six.integer_types or klass in (float, str, bool):
        return _deserialize_primitive(data, klass)
    elif klass == object or klass == dict:
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


def _deserialize_primitive(data: Union[dict, list, str], klass: type) -> Union[int, float, str, bool]:
    """Deserialize to primitive type.

    Parameters
    ----------
    data : dict or list or str
        dict, list or str to deserialize.
    klass : type
        Class literal, or string of class name.

    Returns
    -------
    int or float or str or bool
        Deserialized data.
    """
    try:
        value = klass(data)
    except UnicodeEncodeError:
        value = six.u(data)
    except TypeError:
        value = data
    return value


def _deserialize_object(value: object) -> object:
    """Return a original value.

    Parameters
    ----------
    value : object
        Object to be deserialized.

    Returns
    -------
    object
        Original object.
    """
    return value


def deserialize_date(string: str) -> Union[datetime.date, str]:
    """Deserialize string to date.

    Parameters
    ----------
    string : object
        String to be deserialized to date.

    Returns
    -------
    datetime.date or str
        Deserialized date or string in case of ImportError.
    """
    try:
        from dateutil.parser import parse
        return parse(string).date()
    except ImportError:
        return string


def deserialize_datetime(string: str) -> Union[datetime.datetime, str]:
    """Deserialize string to datetime.

    The string should be in iso8601 datetime format.

    Parameters
    ----------
    string : object
        String to be deserialized to date.

    Returns
    -------
    datetime.datetime or str
        Deserialized datetime or string in case of ImportError.
    """
    try:
        from dateutil.parser import parse
        return parse(string)
    except ImportError:
        return string


def deserialize_model(data: Union[list, dict], klass: type):
    """Deserialize list or dict to Model.

    Parameters
    ----------
    data : list or dict
        dict, list or str to deserialize.
    klass : type
        Class literal, or string of class name.

    Returns
    -------
    Model or list or dict
        Deserialized data to Model or data without changes.
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


def _deserialize_list(data: list, boxed_type: type) -> list:
    """Deserialize a list and its elements.

    Parameters
    ----------
    data : list
        list to deserialize.
    boxed_type : type
        Class literal.

    Returns
    -------
    list
        Deserialized list.
    """
    return [_deserialize(sub_data, boxed_type)
            for sub_data in data]


def _deserialize_dict(data: dict, boxed_type: type) -> dict:
    """Deserialize a dict and its elements.

    Parameters
    ----------
    data : dict
        dict to deserialize.
    boxed_type : type
        Class literal.

    Returns
    -------
    dict
        Deserialized dict.
    """
    return {k: _deserialize(v, boxed_type)
            for k, v in six.iteritems(data)}


def remove_nones_to_dict(dct: dict) -> dict:
    """Remove None values from a dict recursively.

    Parameters
    ----------
    dct : dict
        Dictionary with the None values to be removed.

    Returns
    -------
    dict
        Dictionary with the None values removed.
    """
    return {k: v if not isinstance(v, dict) else remove_nones_to_dict(v)
            for k, v in dct.items() if v is not None}


def parse_api_param(param: str, param_type: str) -> Union[typing.Dict, None]:
    """Parse a str parameter from the API query and returns a dictionary the framework can process.

    Parameters
    ----------
    param : str
        String parameter coming from the API.
    param_type : str
        Type of parameter: search or sort.

    Returns
    -------
    dict
        Dictionary that the framework can process.
    """
    if param is not None:
        my_func = f'_parse_{param_type}_param'
        parser = globals().get(my_func, lambda x: x)
        return parser(param)
    else:
        return param


def _parse_search_param(search: str) -> typing.Dict:
    """Parse search str param coming from the API query into a dictionary the framework can process.

    Parameters
    ----------
    search : str
        Search parameter coming from the API query.

    Returns
    -------
    dict
        Dictionary that the framework can process.
    """
    negation = search[0] == '-'
    return {'negation': negation, 'value': search[1:] if negation else search}


def _parse_sort_param(sort: str) -> typing.Dict:
    """Parse sort str param coming from the API query into a dictionary the framework can process.

    Parameters
    ----------
    sort : str
        Sort parameter coming from the API query.

    Returns
    -------
    dict
        Dictionary that the framework can process.
    """
    sort_fields = sort[(1 if sort[0] == '-' or sort[0] == '+' else 0):]
    return {'fields': sort_fields.split(','), 'order': 'desc' if sort[0] == '-' else 'asc'}


def _parse_q_param(query: str) -> str:
    """Search and parse q parameter inside the query string.

    Parameters
    ----------
    query : str
        String query which can contain q parameter.

    Returns
    -------
    str
        Parsed query.
    """
    q = next((q for q in query.split('&') if q.startswith('q=')), None)

    if q:
        return q[2:]


def to_relative_path(full_path: str) -> str:
    """Return a relative path from Wazuh base directory.

    Parameters
    ----------
    full_path : str
        Full path.

    Returns
    -------
    str
        Relative path from Wazuh base directory.
    """
    return os.path.relpath(full_path, common.WAZUH_SHARE)


def _create_problem(exc: Exception, code: int = None):
    """Transform an exception into a ProblemException according to `exc`.

    Parameters
    ----------
    exc : Exception
        If `exc` is an instance of `WazuhException` it will be casted into a ProblemException,
        otherwise it will be raised.
    code : int
        HTTP status code for this response.

    Raises
    ------
    Exception
        ProblemException or `exc` exception type.
    """
    ext = None
    if isinstance(exc, exception.WazuhException):
        ext = remove_nones_to_dict({'remediation': exc.remediation,
                                    'code': exc.code,
                                    'dapi_errors': exc.dapi_errors if exc.dapi_errors != {} else None
                                    })

    if isinstance(exc, exception.WazuhInternalError):
        raise ProblemException(status=500 if not code else code,
                               type=exc.type, title=exc.title, detail=exc.message, ext=ext)
    elif isinstance(exc, exception.WazuhPermissionError):
        raise ProblemException(status=403, type=exc.type, title=exc.title, detail=exc.message, ext=ext)
    elif isinstance(exc, exception.WazuhResourceNotFound):
        raise ProblemException(status=404, type=exc.type, title=exc.title, detail=exc.message, ext=ext)
    elif isinstance(exc, exception.WazuhTooManyRequests):
        raise ProblemException(status=429, type=exc.type, title=exc.title, detail=exc.message, ext=ext)
    elif isinstance(exc, exception.WazuhNotAcceptable):
        raise ProblemException(status=406, type=exc.type, title=exc.title, detail=exc.message, ext=ext)
    elif isinstance(exc, exception.WazuhError):
        raise ProblemException(status=400 if not code else code,
                               type=exc.type, title=exc.title, detail=exc.message, ext=ext)

    raise exc


def raise_if_exc(obj: object) -> Union[object, None]:
    """Check if obj is an Exception and raises it. Otherwise it is returned.

    Parameters
    ----------
    obj : object
        Object to be checked

    Returns
    -------
    object
        An object only if obj is not an Exception instance.
    """
    if isinstance(obj, Exception):
        _create_problem(obj)
    else:
        return obj


def get_invalid_keys(original_dict: dict, des_dict: dict) -> set:
    """Return a set with the keys from `original_dict` that are not present in `des_dict`.

    Parameters
    ----------
    original_dict : dict
        Original dictionary.
    des_dict : dict
        Deserialized dictionary with the model keys.

    Returns
    -------
    set
        Set with the invalid keys.
    """
    invalid_keys = set()

    for key in original_dict:
        if isinstance(original_dict[key], dict):
            try:
                invalid_keys.update(get_invalid_keys(original_dict[key], des_dict[key]))
            except KeyError:
                invalid_keys.add(key)
        else:
            if key not in set(des_dict):
                invalid_keys.add(key)

    return invalid_keys


def deprecate_endpoint(link: str = ''):
    """Decorator to add deprecation headers to API response.

    Parameters
    ----------
    link : str
        Documentation related to this deprecation.
    """

    def add_deprecation_headers(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            api_response = await func(*args, **kwargs)

            api_response.headers['Deprecated'] = 'true'
            if link:
                api_response.headers['Link'] = f'<{link}>; rel="Deprecated"'

            return api_response

        return wrapper

    return add_deprecation_headers


def only_master_endpoint(func):
    """Decorator used to restrict endpoints only on master node."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not running_in_master_node():
            raise_if_exc(exception.WazuhResourceNotFound(902))
        else:
            return (await func(*args, **kwargs))

    return wrapper
