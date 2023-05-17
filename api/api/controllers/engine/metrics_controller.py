# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Optional

from wazuh.engine.request_builder import EngineRequestBuilder
from wazuh.engine.commands import MetricCommand

logger = logging.getLogger('wazuh-api')

# TODO Redefine HARDCODED values
# TODO Define the max number of limit
HARDCODED_VALUE_TO_SPECIFY = 10000
HARDCODED_ORIGIN_NAME = "metric"
HARDCODED_ORIGIN_MODULE = "metric"
ENGINE_METRICS_VERSION = 1


async def get_metrics(request, scope_name: Optional[str] = None,  instrument_name: Optional[str] = None,
                      select: Optional[str] = None, sort: Optional[str] = None, search: Optional[str] = None,
                      offset: int = 0, limit: int = HARDCODED_VALUE_TO_SPECIFY):
    """Get a single metric or all the collected metrics. Uses the metrics/get and metrics/dump actions
    of the engine.

    Parameters
    ----------
    request : connexion.request
    scope_name: Optional[str]
        Name of the metric scope.  If it is None and the instrument_name is None, returns all
        metrics.
    instrument_name: Optional[str]
        Name of the metric instrument. If it is None and the scope_name is None, returns all
        metrics.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: HARDCODED_VALUE_TO_SPECIFY


    Returns
    -------
    TODO
    """
    request_builder = EngineRequestBuilder(ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)

    if scope_name is None and instrument_name is None:
        request_builder.add_command(command=MetricCommand.DUMP)
    elif scope_name is None:
        #TODO Error Instrument name must be None too
        return
    elif instrument_name is None:
        #TODO Error Scope name must be None too
        return
    else:
        request_builder.add_command(command=MetricCommand.LIST)
        request_builder.add_parameters(parameters={"scopeName": scope_name, "instrumentName": instrument_name})

    return


async def get_instruments(request, select: Optional[str] = None, sort: Optional[str] = None,
                          search: Optional[str] = None, offset: int = 0, limit: int = HARDCODED_VALUE_TO_SPECIFY):
    """Get all name, status and instruments types. Uses the metrics/list action
    of the engine.

    Parameters
    ----------
    request : connexion.request
    select : Optional[str]
        Select which fields to return (separated by comma).
    sort :Optional[str]
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : Optional[str]
        Look for elements with the specified string.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: HARDCODED_VALUE_TO_SPECIFY


    Returns
    -------
    TODO
    """
    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.LIST)

    return


async def enable_metric(request, scope_name: Optional[str] = None, instrument_name: Optional[str] = None,
                        enable: bool = True):
    """Enable or disable a specified metric. Uses the metrics/enable action
    of the engine.

    Parameters
    ----------
    request : connexion.request
    scope_name: Optional[str]
        Name of the metric scope.  If it is None and the instrument_name is None, returns all
        metrics.
    instrument_name: Optional[str]
        Name of the metric instrument. If it is None and the scope_name is None, returns all
        metrics.
    enable: bool
        Enable of disable the metric. True represent enable, false disable.

    Returns
    -------
    TODO
    """
    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.ENABLE)
    request_builder.add_parameters({
        "scopeName": scope_name,
        "instrumentName": instrument_name,
        "status": enable
    })

    return


async def test_dummy_metric(request):
    """Generate dummy metrics for testing.

    Parameters
    ----------
    request : connexion.request

    Returns
    -------
    TODO
    """
    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.TEST)

    return
