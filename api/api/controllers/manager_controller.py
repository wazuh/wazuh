# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import datetime
import logging

import connexion
from dateutil.parser import parse

import wazuh.configuration as configuration
import wazuh.manager as manager
import wazuh.stats as stats
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh import Wazuh
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_status(pretty=False, wait_for_complete=False):
    """Get a specified node's status 

    Returns the status of all Wazuh daemons in node node_id

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.status,
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
def get_info(pretty=False, wait_for_complete=False):
    """Get a specified node's information 

    Returns basic information about a specified node such as version, compilation date, installation path.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=Wazuh().to_dict,
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
def get_configuration(pretty=False, wait_for_complete=False, section=None, field=None):
    """Get a specified node's configuration 

    Returns wazuh configuration used in node {node_id}

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param section: Indicates the wazuh configuration section
    :param field: Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    """
    f_kwargs = {'section': section,
                'field': field}

    dapi = DistributedAPI(f=configuration.get_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # if section is not None:
    #     data = data[section]

    response = Data(data)

    return response, 200


@exception_handler
def get_stats(pretty=False, wait_for_complete=False, date=None):
    """Get a specified node's stats. 

    Returns Wazuh statistical information in node {node_id} for the current or specified date.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param date: Selects the date for getting the statistical information. Format ISO 8601.
    """
    if date:
        today = parse(date)
    else:
        today = datetime.datetime.now()
    year = str(today.year)
    month = str(today.month)
    day = str(today.day)

    f_kwargs = {'year': year, 'month': month, 'day': day, 'date': True if date else False}

    dapi = DistributedAPI(f=stats.totals,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    # 'data' field is included, do not use 'Data model'
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_stats_hourly(pretty=False, wait_for_complete=False):
    """Get a specified node's stats by hour. 

    Returns Wazuh statistical information in node {node_id} per hour. Each number in the averages field represents the average of alerts per hour.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.hourly,
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
def get_stats_weekly(pretty=False, wait_for_complete=False):
    """Get a specified node's stats by week. 

    Returns Wazuh statistical information in node {node_id} per week. Each number in the averages field represents the average of alerts per hour for that specific day.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.weekly,
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
def get_stats_analysisd(pretty=False, wait_for_complete=False):
    """Get a specified node's analysisd stats. 

    Returns Wazuh analysisd statistical information in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.analysisd,
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
def get_stats_remoted(pretty=False, wait_for_complete=False):
    """Get a specified node's remoted stats.

    Returns Wazuh remoted statistical information in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.remoted,
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
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'category': category,
                'type_log': type_log}

    dapi = DistributedAPI(f=manager.ossec_log,
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
def get_log_summary(pretty=False, wait_for_complete=False):
    """Get a summary of a specified node's wazuh logs. 

    Returns a summary of the last 2000 wazuh log entries in node {node_id}.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.ossec_log_summary,
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
def get_files(pretty=False, wait_for_complete=False, path=None):
    """Get file contents.

    Returns file contents from any file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param path: Filepath to return.
    """
    f_kwargs = {'path': path}

    dapi = DistributedAPI(f=manager.get_file,
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
def put_files(body, overwrite=False, pretty=False, wait_for_complete=False, path=None):
    """Updates file contents.

    Replaces file contents with the data contained in the API request.

    :param body: Body request with the content of the file to be uploaded
    :param overwrite: If set to false, an exception will be raised when updating contents of an already existing filename.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param path: Filepath to return.
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

    f_kwargs = {'path': path,
                'overwrite': overwrite,
                'content': body}

    dapi = DistributedAPI(f=manager.upload_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_files(pretty=False, wait_for_complete=False, path=None):
    """Removes a file.

    Removes a specified file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param path: Filepath to return.
    """
    f_kwargs = {'path': path}

    dapi = DistributedAPI(f=manager.delete_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_restart(pretty=False, wait_for_complete=False):
    """Restarts the wazuh manager.

    Restarts the wazuh manager.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.restart,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_conf_validation(pretty=False, wait_for_complete=False):
    """Check Wazuh configuration.

    Returns wether the Wazuh configuration is correct.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.validation,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200

