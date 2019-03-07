# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from wazuh.cluster import cluster
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('agents_controller')
logger.addHandler(logging.StreamHandler())


def get_cluster_node(pretty=False, wait_for_complete=False):
    """Get information about the local node.

    Returns basic information about the cluster node receiving the request.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :rtype: object
    """
    pass


def get_cluster_nodes(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                      search=None, select=None, type=None):
    """Get information about all nodes in the cluster. 

    Returns a list containing all connected nodes in the cluster.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :param search: Looks for elements with the specified string
    :param select: Select which fields to return (separated by comma)
    :param type: Filters by node type.
    """
    pass


def get_cluster_node_info(node_id, pretty=False, wait_for_complete=False, select=None):
    """Get information about a specified node.

    Returns information about a specified node in the cluster.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param select: Select which fields to return (separated by comma)
    """
    pass


def get_healthcheck(pretty=False, wait_for_complete=False):
    """Show cluster healthcheck 

    Returns cluster healthcheck information such as last keep alive, last synchronization time and number of agents reporting on each node.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_healthcheck_node(node_id, pretty=False, wait_for_complete=False):
    """Show a specified node's healthcheck information 

    Returns cluster healthcheck information of an specified node.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_status(pretty=False, wait_for_complete=False):
    """Get cluster status 

    Returns information about the cluster status.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_config(pretty=False, wait_for_complete=False):
    """Get cluster configuration 

    Returns the current cluster configuration

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_status_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's status 

    Returns the status of all Wazuh daemons in node node_id

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_info_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's information 

    Returns basic information about a specified node such as version, compilation date, installation path.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_configuration_node(node_id, pretty=False, wait_for_complete=False, section=None, field=None):
    """Get a specified node's configuration 

    Returns wazuh configuration used in node {node_id}

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param section: Indicates the wazuh configuration section
    :param field: Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    """
    pass


def get_stats_node(node_id, pretty=False, wait_for_complete=False, date=None):
    """Get a specified node's stats. 

    Returns Wazuh statistical information in node {node_id} for the current or specified date.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param date: Selects the date for getting the statistical information. Format YYYYMMDD.
    """
    pass


def get_stats_hourly_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's stats by hour. 

    Returns Wazuh statistical information in node {node_id} per hour. Each number in the averages field represents the average of alerts per hour.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_weekly_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's stats by week. 

    Returns Wazuh statistical information in node {node_id} per week. Each number in the averages field represents the average of alerts per hour for that specific day.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_analysisd_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's analysisd stats. 

    Returns Wazuh analysisd statistical information in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_stats_remoted_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's remoted stats.

    Returns Wazuh remoted statistical information in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_log_node(node_id, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                 search=None, category=None, type_log=None):
    """Get a specified node's wazuh logs. 

    Returns the last 2000 wazuh log entries in node {node_id}.

    :param node_id: Cluster node name.
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


def get_log_summary_node(node_id, pretty=False, wait_for_complete=False):
    """Get a summary of a specified node's wazuh logs. 

    Returns a summary of the last 2000 wazuh log entries in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def get_files_node(node_id, path, pretty=False, wait_for_complete=False):
    """Get file contents from a specified node in the cluster.

    Returns file contents from any file in cluster node {node_id}.

    :param node_id: Cluster node name.
    :param path: Filepath to return.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass

def post_files_node(node_id, path, overwrite=False, pretty=False, wait_for_complete=False):
    """Updates file contents in a specified cluster node.

    Replaces file contents with the data contained in the API request in a specified cluster node.

    :param node_id: Cluster node name.
    :param path: Filepath to return.
    :param overwrite: If set to false, an exception will be raised when updating contents of an already existing filename.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass


def delete_files_node(node_id, path, pretty=False, wait_for_complete=False):
    """Removes a file in a specified cluster node.

    Removes a specified file in the node {node-id}.

    :param node_id: Cluster node name.
    :param path: Filepath to return.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    pass
