# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional

from wazuh.engine.request_builder import EngineRequestBuilder
from wazuh.engine.commands import MetricCommand


# TODO Redefine HARDCODED values
HARDCODED_ORIGIN_NAME = "metric"
HARDCODED_ORIGIN_MODULE = "metric"
ENGINE_METRICS_VERSION = 1


def get_metrics(limit: int, scope_name: Optional[str] = None, instrument_name: Optional[str] = None,
                select: Optional[str] = None, sort: Optional[str] = None, search: Optional[str] = None,
                offset: int = 0):
    """
    Retrieves metrics based on the specified parameters.

    Args:
        limit (int): Maximum number of metrics to retrieve.
        scope_name (Optional[str]): Name of the metric scope.
        instrument_name (Optional[str]): Name of the metric instrument.
        select (Optional[str]): Fields to return (separated by comma).
        sort (Optional[str]): Field(s) to sort the collection by (separated by comma).
        search (Optional[str]): String to search for in the metrics.
        offset (int): Number of elements to skip before returning the collection.

    Returns:
        None
    """

    request_builder = EngineRequestBuilder(ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)

    if scope_name is None and instrument_name is None:
        request_builder.add_command(command=MetricCommand.DUMP)
    elif scope_name is None:
        # TODO Error: Instrument name must be None too
        return
    elif instrument_name is None:
        # TODO Error: Scope name must be None too
        return
    else:
        request_builder.add_command(command=MetricCommand.LIST)
        request_builder.add_parameters(parameters={"scopeName": scope_name, "instrumentName": instrument_name})


def get_instruments(limit: int, select: Optional[str] = None, sort: Optional[str] = None,
                    search: Optional[str] = None, offset: int = 0):
    """
    Retrieves information about instruments.

    Args:
        limit (int): Maximum number of instruments to retrieve.
        select (Optional[str]): Fields to return (separated by comma).
        sort (Optional[str]): Field(s) to sort the collection by (separated by comma).
        search (Optional[str]): String to search for in the instruments.
        offset (int): Number of elements to skip before returning the collection.

    Returns:
        None
    """

    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.LIST)


def enable_instrument(scope_name: Optional[str] = None, instrument_name: Optional[str] = None,
                  enable: bool = True):
    """
    Enables or disables a specified metric.

    Args:
        scope_name (Optional[str]): Name of the metric scope.
        instrument_name (Optional[str]): Name of the metric instrument.
        enable (bool): True to enable the metric, False to disable.

    Returns:
        None
    """

    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.ENABLE)
    request_builder.add_parameters({
        "scopeName": scope_name,
        "instrumentName": instrument_name,
        "status": enable
    })


def get_test_dummy_metric():
    """
    Retrieves a test dummy metric.

    Returns:
        None
    """

    request_builder = EngineRequestBuilder(version=ENGINE_METRICS_VERSION)
    request_builder.add_origin(name=HARDCODED_ORIGIN_NAME, module=HARDCODED_ORIGIN_MODULE)
    request_builder.add_command(command=MetricCommand.TEST)
