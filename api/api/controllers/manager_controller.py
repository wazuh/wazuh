# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import logging
from typing import Union

from aiohttp import web
from connexion.lifecycle import ConnexionResponse

import wazuh.manager as manager
import wazuh.stats as stats
from api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from api.encoder import dumps, prettify
from api.models.base_model_ import Body
from api.util import (
    deprecate_endpoint, deserialize_date, only_master_endpoint, parse_api_param, raise_if_exc, remove_nones_to_dict
)
from api.validator import check_component_configuration_pair
from wazuh.core import common
from wazuh.core import configuration
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.manager import query_update_check_service
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def get_status(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's Wazuh daemons status

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.get_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_info(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's basic information

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.get_basic_info,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_configuration(request, pretty: bool = False, wait_for_complete: bool = False, section: str = None,
                            field: str = None, raw: bool = False,
                            distinct: bool = False) -> Union[web.Response, ConnexionResponse]:
    """Get manager's or local_node's configuration (ossec.conf)

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format. It only works when `raw` is False (JSON format). Default `False`
    wait_for_complete : bool, optional
        Disable response timeout or not. Default `False`
    section : str
        Indicates the wazuh configuration section
    field : str
        Indicates a section child, e.g, fields for rule section are include, decoder_dir, etc.
    raw : bool, optional
        Whether to return the file content in raw or JSON format. Default `False`
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response or ConnexionResponse
        Depending on the `raw` parameter, it will return a web.Response object or a ConnexionResponse object:
            raw=True            -> ConnexionResponse (application/xml)
            raw=False (default) -> web.Response (application/json)
        If any exception was raised, it will return a web.Response with details.
    """
    f_kwargs = {'section': section,
                'field': field,
                'raw': raw,
                'distinct': distinct}

    dapi = DistributedAPI(f=manager.read_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    if isinstance(data, AffectedItemsWazuhResult):
        response = web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
    else:
        response = ConnexionResponse(body=data["message"], mimetype='application/xml', content_type='application/xml')
    return response


async def get_daemon_stats(request, pretty: bool = False, wait_for_complete: bool = False, daemons_list: list = None):
    """Get Wazuh statistical information from the specified manager's daemons.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    daemons_list : list
        List of the daemons to get statistical information from.
    """
    daemons_list = daemons_list or []
    f_kwargs = {'daemons_list': daemons_list}

    dapi = DistributedAPI(f=stats.get_daemons_stats,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'])
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_stats(request, pretty: bool = False, wait_for_complete: bool = False, date: str = None) -> web.Response:
    """Get manager's or local_node's stats.

    Returns Wazuh statistical information for the current or specified date.

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable response timeout or not.
    date : str
        Selects the date for getting the statistical information. Format ISO 8601.

    Returns
    -------
    web.Response
        API response.
    """
    if not date:
        date = datetime.datetime.today()
    else:
        date = deserialize_date(date)

    f_kwargs = {'date': date}

    dapi = DistributedAPI(f=stats.totals,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_stats_hourly(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's stats by hour.

    Returns Wazuh statistical information per hour. Each number in the averages field represents the average of alerts
    per hour.

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable response timeout or not.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.hourly,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_stats_weekly(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's stats by week.

    Returns Wazuh statistical information per week. Each number in the averages field represents the average of alerts
    per hour for that specific day.

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable response timeout or not.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=stats.weekly,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
async def get_stats_analysisd(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's analysisd statistics.

    Notes
    -----
    To be deprecated in v5.0.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Whether to disable response timeout or not. Default `False`

    Returns
    -------
    web.Response
    """
    f_kwargs = {'filename': common.ANALYSISD_STATS}

    dapi = DistributedAPI(f=stats.deprecated_get_daemons_stats,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
async def get_stats_remoted(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's remoted statistics.

    Notes
    -----
    To be deprecated in v5.0.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Whether to disable response timeout or not. Default `False`

    Returns
    -------
    web.Response
    """
    f_kwargs = {'filename': common.REMOTED_STATS}

    dapi = DistributedAPI(f=stats.deprecated_get_daemons_stats,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_log(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                  sort: str = None, search: str = None, tag: str = None, level: str = None,
                  q: str = None, select: str = None, distinct: bool = False) -> web.Response:
    """Get manager's or local_node's last 2000 wazuh log entries.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    tag : bool
        Filters by category/tag of log.
    level : str
        Filters by log level.
    q : str
        Query to filter agents by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['timestamp'],
                'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'tag': tag,
                'level': level,
                'q': q,
                'select': select,
                'distinct': distinct}

    dapi = DistributedAPI(f=manager.ossec_log,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_log_summary(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get manager's or local_node's summary of the last 2000 wazuh log entries.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.ossec_log_summary,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_api_config(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get active API configuration in manager or local_node.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.get_api_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_restart(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Restart manager or local_node.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.restart,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_conf_validation(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Check if Wazuh configuration is correct in manager or local_node.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=manager.validation,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_manager_config_ondemand(request, component: str, pretty: bool = False, wait_for_complete: bool = False,
                                      **kwargs: dict) -> web.Response:
    """Get active configuration in manager or local_node for one component [on demand].

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    component : str
        Specified component.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'component': component,
                'config': kwargs.get('configuration', None)
                }

    raise_if_exc(check_component_configuration_pair(f_kwargs['component'], f_kwargs['config']))

    dapi = DistributedAPI(f=manager.get_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def update_configuration(request, body: bytes, pretty: bool = False,
                               wait_for_complete: bool = False) -> web.Response:
    """Update manager's or local_node's configuration (ossec.conf).

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    body : bytes
        New ossec.conf configuration.

    Returns
    -------
    web.Response
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'new_conf': parsed_body}

    dapi = DistributedAPI(f=manager.update_ossec_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@only_master_endpoint
async def check_available_version(
        request: web.Request, pretty: bool = False, force_query: bool = False
) -> web.Response:
    """Get available update information.

    Parameters
    ----------
    request : web.Request
        API request.
    pretty : bool, optional
        Show results in human-readable format, by default False.
    force_query : bool, optional
        Make the query to the CTI service on demand, by default False.

    Returns
    -------
    web.Response
        API response.
    """

    if force_query and configuration.update_check_is_enabled():
        logger.debug('Forcing query to the update check service...')
        dapi = DistributedAPI(f=query_update_check_service,
                              f_kwargs={
                                  INSTALLATION_UID_KEY: request.app[INSTALLATION_UID_KEY]
                              },
                              request_type='local_master',
                              is_async=True,
                              logger=logger
                              )
        update_information = raise_if_exc(await dapi.distribute_function())
        request.app[UPDATE_INFORMATION_KEY] = update_information.dikt

    dapi = DistributedAPI(f=manager.get_update_information,
                          f_kwargs={
                              UPDATE_INFORMATION_KEY: request.app.get(UPDATE_INFORMATION_KEY, {})
                          },
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
