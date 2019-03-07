# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from wazuh import manager
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('agents_controller')
logger.addHandler(logging.StreamHandler())


def get_config(pretty=False, wait_for_complete=False):
    """Get cluster configuration 

    Returns the current cluster configuration

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_status(pretty=False, wait_for_complete=False):
    """Get a specified node's status 

    Returns the status of all Wazuh daemons in node node_id

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_info(pretty=False, wait_for_complete=False):
    """Get a specified node's information 

    Returns basic information about a specified node such as version, compilation date, installation path.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_configuration(pretty=False, wait_for_complete=False, section=None, field=None):
    """Get a specified node's configuration 

    Returns wazuh configuration used in node {node_id}

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param section: Indicates the wazuh configuration section
    :param field: Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    """
    pass


def get_stats(pretty=False, wait_for_complete=False, date=None):
    """Get a specified node's stats. 

    Returns Wazuh statistical information in node {node_id} for the current or specified date.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param date: Selects the date for getting the statistical information. Format YYYYMMDD.
    """
    pass


def get_stats_hourly(pretty=False, wait_for_complete=False):
    """Get a specified node's stats by hour. 

    Returns Wazuh statistical information in node {node_id} per hour. Each number in the averages field represents the average of alerts per hour.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_weekly(pretty=False, wait_for_complete=False):
    """Get a specified node's stats by week. 

    Returns Wazuh statistical information in node {node_id} per week. Each number in the averages field represents the average of alerts per hour for that specific day.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_analysisd(pretty=False, wait_for_complete=False):
    """Get a specified node's analysisd stats. 

    Returns Wazuh analysisd statistical information in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_remoted(pretty=False, wait_for_complete=False):
    """Get a specified node's remoted stats.

    Returns Wazuh remoted statistical information in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_log(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                 search=None, category=None, type_log=None):
    """Get a specified node's wazuh logs. 

    Returns the last 2000 wazuh log entries in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :param search: Looks for elements with the specified string
    :param category: Filter by category of log.
    :param type_log: Filters by log level.
    """
    pass


def get_log_summary(pretty=False, wait_for_complete=False):
    """Get a summary of a specified node's wazuh logs. 

    Returns a summary of the last 2000 wazuh log entries in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass
