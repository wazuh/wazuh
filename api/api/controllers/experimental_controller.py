# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from functools import wraps

from connexion import request
from connexion.lifecycle import ConnexionResponse

import wazuh.ciscat as ciscat
import wazuh.rootcheck as rootcheck
import wazuh.syscheck as syscheck
import wazuh.syscollector as syscollector
from api import configuration
from api.controllers.util import json_response
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhResourceNotFound

logger = logging.getLogger('wazuh-api')


def check_experimental_feature_value(func):
    """Decorator used to check whether the experimental features are enabled in the API configuration or not."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not configuration.api_conf['experimental_features']:
            raise_if_exc(WazuhResourceNotFound(1122))
        else:
            return await func(*args, **kwargs)

    return wrapper


@check_experimental_feature_value
async def get_cis_cat_results(pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*',
                              offset: int = 0, limit: int = None, select: str = None, sort: str = None,
                              search: str = None, benchmark: str = None, profile: str = None, fail: int = None,
                              error: int = None, notchecked: int = None, unknown: int = None,
                              score: int = None) -> ConnexionResponse:
    """Get ciscat results info from all agents or a list of them.

    Parameters
    ----------
    agents_list : str
        List of agent's IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    benchmark : str
        Filters by benchmark type.
    profile : str
        Filters by evaluated profile.
    fail : int
        Filters by failed checks.
    error : int
        Filters by encountered errors.
    notchecked : int
        Filters by notchecked value.
    unknown : int
        Filters by unknown results.
    score : int
        Filters by final score.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'filters': {
                    'benchmark': benchmark,
                    'profile': profile,
                    'fail': fail,
                    'error': error,
                    'notchecked': notchecked,
                    'unknown': unknown,
                    'score': score,
                    'pass': request.query_params.get('pass', None)
                }
                }

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
