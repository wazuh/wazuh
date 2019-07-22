# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import connexion
import datetime
import logging

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
import wazuh.cluster.cluster as cluster
import wazuh.cluster.control as cluster_control
import wazuh.configuration as configuration
from wazuh import Wazuh
from wazuh import common
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError
import wazuh.manager as manager
import wazuh.stats as stats


loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_cluster_node(pretty=False, wait_for_complete=False):
    """Get information about the local node.

    Returns basic information about the cluster node receiving the request.

    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :rtype: object
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=cluster.get_node,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_cluster_nodes(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                      search=None, select=None):
    """Get information about all nodes in the cluster. 

    Returns a list containing all connected nodes in the cluster.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    """
    # get type parameter from query
    type_ = connexion.request.args.get('type', 'all')

    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'filter_type': type_}

    dapi = DistributedAPI(f=cluster_control.get_nodes,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          local_client_arg='lc'
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_cluster_node_info(node_id, pretty=False, wait_for_complete=False, select=None):
    """Get information about a specified node.

    Returns information about a specified node in the cluster.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param select: Select which fields to return (separated by comma)
    """
    f_kwargs = {'filter_node': node_id,
                'select': select}

    dapi = DistributedAPI(f=cluster_control.get_node,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          local_client_arg='lc'
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_healthcheck(pretty=False, wait_for_complete=False):
    """Show cluster healthcheck 

    Returns cluster healthcheck information such as last keep alive, last synchronization time and number of agents reporting on each node.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=cluster_control.get_health,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          local_client_arg='lc'
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_healthcheck_node(node_id, pretty=False, wait_for_complete=False):
    """Show a specified node's healthcheck information 

    Returns cluster healthcheck information of an specified node.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'filter_node': node_id}

    dapi = DistributedAPI(f=cluster_control.get_health,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          local_client_arg='lc'
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_status(pretty=False, wait_for_complete=False):
    """Get cluster status 

    Returns information about the cluster status.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=cluster.get_status_json,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_config(pretty=False, wait_for_complete=False):
    """Get cluster configuration 

    Returns the current cluster configuration

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=cluster.read_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_status_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's status 

    Returns the status of all Wazuh daemons in node node_id

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=manager.status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_info_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's information 

    Returns basic information about a specified node such as version, compilation date, installation path.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=Wazuh(common.ossec_path).get_ossec_init,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_configuration_node(node_id, pretty=False, wait_for_complete=False, section=None, field=None):
    """Get a specified node's configuration 

    Returns wazuh configuration used in node {node_id}

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param section: Indicates the wazuh configuration section
    :param field: Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    """
    f_kwargs = {'node_id': node_id,
                'section': section,
                'field': field}

    dapi = DistributedAPI(f=configuration.get_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_stats_node(node_id, pretty=False, wait_for_complete=False, date=None):
    """Get a specified node's stats. 

    Returns Wazuh statistical information in node {node_id} for the current or specified date.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param date: Selects the date for getting the statistical information. Format YYYY-MM-DD.
    """
    if date:
        try:
            year, month, day = date.split('-')
        except ValueError:
            raise WazuhError(1412)

    else:
        today = datetime.datetime.now()
        year = str(today.year)
        month = str(today.month)
        day = str(today.day)

    f_kwargs = {'node_id': node_id,
                'year': year,
                'month': month,
                'day': day}

    dapi = DistributedAPI(f=stats.totals,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_stats_hourly_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's stats by hour. 

    Returns Wazuh statistical information in node {node_id} per hour. Each number in the averages field represents the average of alerts per hour.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=stats.hourly,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_stats_weekly_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's stats by week. 

    Returns Wazuh statistical information in node {node_id} per week. Each number in the averages field represents the average of alerts per hour for that specific day.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=stats.weekly,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_stats_analysisd_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's analysisd stats. 

    Returns Wazuh analysisd statistical information in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=stats.analysisd,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_stats_remoted_node(node_id, pretty=False, wait_for_complete=False):
    """Get a specified node's remoted stats.

    Returns Wazuh remoted statistical information in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=stats.remoted,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
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
    f_kwargs = {'node_id': node_id,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'category': category,
                'type_log': type_log}

    dapi = DistributedAPI(f=manager.ossec_log,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_log_summary_node(node_id, pretty=False, wait_for_complete=False):
    """Get a summary of a specified node's wazuh logs. 

    Returns a summary of the last 2000 wazuh log entries in node {node_id}.

    :param node_id: Cluster node name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=manager.ossec_log_summary,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_files_node(node_id, path, pretty=False, wait_for_complete=False):
    """Get file contents from a specified node in the cluster.

    Returns file contents from any file in cluster node {node_id}.

    :param node_id: Cluster node name.
    :param path: Filepath to return.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id,
                'path': path}

    dapi = DistributedAPI(f=manager.get_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_files_node(body, node_id, path, overwrite=False, pretty=False, wait_for_complete=False):
    """Updates file contents in a specified cluster node.

    Replaces file contents with the data contained in the API request in a specified cluster node.

    :param body: Body request with the content of the file to be uploaded
    :param node_id: Cluster node name
    :param path: Filepath to upload the new file
    :param overwrite: If set to false, an exception will be raised when updating contents of an already existing filename.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    # get content-type from headers
    try:
        content_type = connexion.request.headers['Content-type']
    except KeyError:
        raise WazuhError(1910)

    # parse body to utf-8
    try:
        body = body.decode('utf-8')
    except UnicodeDecodeError:
        raise WazuhError(1911)
    except AttributeError:
        raise WazuhError(1912)

    f_kwargs = {'node_id': node_id,
                'path': path,
                'overwrite': overwrite,
                'content': body}

    dapi = DistributedAPI(f=manager.upload_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_files_node(node_id, path, pretty=False, wait_for_complete=False):
    """Removes a file in a specified cluster node.

    Removes a specified file in the node {node-id}.

    :param node_id: Cluster node name.
    :param path: Filepath to delete.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'node_id': node_id,
                'path': path}

    dapi = DistributedAPI(f=manager.delete_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_restart(pretty=False, wait_for_complete=False):
    """Restarts all nodes in cluster.

    Restarts all nodes in cluster.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=cluster.restart_all_nodes,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          broadcasting=True
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_restart_node(node_id, pretty=False, wait_for_complete=False):
    """Restarts a specific node in cluster.

    Restarts a specific node in cluster.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param node_id: Cluster node name.
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=manager.restart,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_conf_validation(pretty=False, wait_for_complete=False):
    """Check Wazuh configuration in all cluster nodes.

    Returns wether the Wazuh configuration in all cluster nodes is correct.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.validation,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          broadcasting=True
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_conf_validation_node(node_id, pretty=False, wait_for_complete=False):
    """Check Wazuh configuration in a cluster node

    Returns wether the Wazuh configuration in node {node_id} is correct.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param node_id: Cluster node name.
    """
    f_kwargs = {'node_id': node_id}

    dapi = DistributedAPI(f=manager.validation,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200
