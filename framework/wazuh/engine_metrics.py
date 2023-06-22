# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional, List, Dict, Any

from wazuh.core.engine.commands import MetricCommand

from wazuh.core.common import ENGINE_SOCKET
from wazuh.core.results import WazuhResult
from wazuh.core.exception import WazuhError, WazuhResourceNotFound, WazuhInternalError
from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.utils import process_array

# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "metric"
HARDCODED_ORIGIN_MODULE = "metric"


def normalize_metrics(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalizes the input data by transforming it into a list of dictionaries.

    Parameters
    ---------
    data: Dict[str, Any]
        The input data containing the metrics

    Returns
    ---------
    List[Dict[str, Any]]
        The normalized list of dictionaries wit the metrics data.

    """
    new_list = []
    for key, value in data.items():
        if value and isinstance(value, dict):
            for instrument in value.values():
                instrument_dict = instrument
                instrument_dict['scope_name'] = key
                new_list.append(instrument_dict)

    return new_list


def get_metrics(
        limit: int,
        scope_name: Optional[str] = None,
        instrument_name: Optional[str] = None,
        select: Optional[List] = None,
        sort_by: dict = None,
        sort_ascending: bool = True,
        search_text: str = None,
        complementary_search: bool = False,
        offset: int = 0,
) -> WazuhResult:
    """
    Retrieves metrics based on the specified parameters.

    Parameters
    ---------
    limit: int
        Maximum number of metrics to retrieve.
    scope_name: Optional[str]
        Name of the metric scope.
    instrument_name: Optional[str]
         Name of the metric instrument.
    select: Optional[str]
        Fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    offset: int
        Number of elements to skip before returning the collection.


    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """

    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    if scope_name is None and instrument_name is None:
        msg = create_wazuh_socket_message(origin, MetricCommand.DUMP.value)
    elif scope_name is None:
        raise WazuhError(9003)
    elif instrument_name is None:
        raise WazuhError(9003)
    else:
        parameters = {
            "scopeName": scope_name,
            "instrumentName": instrument_name
        }
        msg = create_wazuh_socket_message(origin, MetricCommand.GET.value, parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if f'The {scope_name} scope has not been created' in result['error']:
            raise WazuhResourceNotFound(9000)
        elif f'scope does not have {instrument_name} instrument' in result['error']:
            raise WazuhResourceNotFound(9001)
        else:
            raise WazuhInternalError(9002)

    normalized_result = normalize_metrics(result['value'])
    final_result = process_array(normalized_result, limit=limit, offset=offset, select=select, sort_by=sort_by,
                                 sort_ascending=sort_ascending, search_text=search_text,
                                 complementary_search=complementary_search)
    return WazuhResult({'data': final_result['items']})


def get_instruments(
        limit: int,
        select: Optional[List] = None,
        sort_by: dict = None,
        sort_ascending: bool = True,
        search_text: str = None,
        complementary_search: bool = False,
        offset: int = 0,
):
    """
    Retrieves information about instruments.

    Parameters
    ---------
    limit: int
        Maximum number of metrics to retrieve.
    select: Optional[str]
        Fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    offset: int
        Number of elements to skip before returning the collection.

    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    msg = create_wazuh_socket_message(origin, MetricCommand.LIST.value)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()
    result = process_array(result['value'], limit=limit, offset=offset, select=select, sort_by=sort_by,
                           sort_ascending=sort_ascending, search_text=search_text,
                           complementary_search=complementary_search)
    return WazuhResult({'data': result['items']})


def enable_instrument(
        scope_name: str,
        instrument_name: str,
        enable: bool,
):
    """
    Enables or disables a specified metric.

    Parameters
    ---------
    scope_name: str
        Name of the metric scope
    instrument_name: str
        Name of the metric instrument
    enable: bool
        True to enable the instrument,  False to disable

    Returns
    ---------
    WazuhResult
        WazuhResult with the results of the command
    """
    origin = {"name": HARDCODED_ORIGIN_NAME, "module": HARDCODED_ORIGIN_MODULE}
    parameters = {
        "scopeName": scope_name,
        "instrumentName": instrument_name,
        "status": enable,
    }
    msg = create_wazuh_socket_message(origin, MetricCommand.ENABLE.value, parameters)

    engine_socket = WazuhSocketJSON(ENGINE_SOCKET)
    engine_socket.send(msg)
    result = engine_socket.receive()

    if result['status'] == 'ERROR':
        if f'The {scope_name} scope has not been created' in result['error']:
            raise WazuhResourceNotFound(9000)
        elif f'scope does not have {instrument_name} instrument' in result['error']:
            raise WazuhResourceNotFound(9001)
        else:
            raise WazuhInternalError(9002)

    return WazuhResult({'message': result['status']})

