# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import logging

from aiohttp import web
from dateutil.parser import parse

import wazuh.manager as manager
import wazuh.stats as stats
from api.encoder import dumps
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import common
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError

logger = logging.getLogger('wazuh')


async def get_status(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's Wazuh daemons status

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.get_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_info(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's basic information

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.get_basic_info,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_configuration(request, pretty=False, wait_for_complete=False, section=None, field=None):
    """Get manager's or local_node's configuration (ossec.conf)

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param section: Indicates the wazuh configuration section
    :param field: Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    """
    f_kwargs = {'section': section,
                'field': field}

    dapi = DistributedAPI(f=manager.read_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_stats(request, pretty=False, wait_for_complete=False, date=None):
    """Get manager's or local_node's stats.

    Returns Wazuh statistical information for the current or specified date.

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

    f_kwargs = {'year': year,
                'month': month,
                'day': day,
                'date': True if date else False}

    dapi = DistributedAPI(f=stats.totals,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_stats_hourly(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's stats by hour.

    Returns Wazuh statistical information per hour. Each number in the averages field represents the average of alerts
    per hour.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = Data(data)

    return web.json_response(data=response, status=200, dumps=dumps)


async def get_stats_weekly(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's stats by week.

    Returns Wazuh statistical information per week. Each number in the averages field represents the average of alerts
    per hour for that specific day.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = Data(data)

    return web.json_response(data=response, status=200, dumps=dumps)


async def get_stats_analysisd(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's analysisd stats.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'filename': common.analysisd_stats}

    dapi = DistributedAPI(f=stats.get_daemons_stats,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = Data(data)

    return web.json_response(data=response, status=200, dumps=dumps)


async def get_stats_remoted(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's remoted stats.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'filename': common.remoted_stats}

    dapi = DistributedAPI(f=stats.get_daemons_stats,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = Data(data)

    return web.json_response(data=response, status=200, dumps=dumps)


async def get_log(request, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                  search=None, category=None, type_log=None):
    """Get manager's or local_node's last 2000 wazuh log entries.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param category: Filter by category of log.
    :param type_log: Filters by log level.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['timestamp'],
                'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'category': category,
                'type_log': type_log}

    dapi = DistributedAPI(f=manager.ossec_log,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_log_summary(request, pretty=False, wait_for_complete=False):
    """Get manager's or local_node's summary of the last 2000 wazuh log entries.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_files(request, pretty=False, wait_for_complete=False, path=None):
    """Get file contents in manager or local_node.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def put_files(request, body, overwrite=False, pretty=False, wait_for_complete=False, path=None):
    """Upload file in manager or local_node.

    :param body: Body request with the content of the file to be uploaded
    :param overwrite: If set to false, an exception will be raised when updating contents of an already existing
    filename.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param path: Filepath to return.
    """
    # Parse body to utf-8
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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def delete_files(request, pretty=False, wait_for_complete=False, path=None):
    """Delete file in manager or local_node.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def put_restart(request, pretty=False, wait_for_complete=False):
    """Restart manager or local_node.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_conf_validation(request, pretty=False, wait_for_complete=False):
    """Check if Wazuh configuration is correct in manager or local_node.

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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_manager_config_ondemand(request, component, pretty=False, wait_for_complete=False, **kwargs):
    """Get active configuration in manager or local_node for one component [on demand]

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param component: Specified component.
    """
    f_kwargs = {'component': component,
                'config': kwargs.get('configuration', None)
                }

    dapi = DistributedAPI(f=manager.get_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)
