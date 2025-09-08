# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh import content as content_framework
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')

async def get_content_status(pretty: bool = False, wait_for_complete: bool = False):
    """
    Get the status of all available content.

    Parameters
    ----------
    pretty : bool, optional
        Whether to pretty-print the response.
    wait_for_complete : bool, optional
        Whether to wait for the operation to complete.

    Returns
    -------
    ConnexionResponse
        API response with the operation result.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=content_framework.get_content_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return json_response(data, pretty=pretty)


async def reload_contents(pretty: bool = False, wait_for_complete: bool = False):
    """
    Reload all content files.

    Parameters
    ----------
    pretty : bool, optional
        Whether to pretty-print the response.
    wait_for_complete : bool, optional
        Whether to wait for the operation to complete.

    Returns
    -------
    ConnexionResponse
        API response with the operation result.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=content_framework.reload_contents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return json_response(data, pretty=pretty)

async def validate_content(pretty: bool = False, wait_for_complete: bool = False):
    """
    Validate all content file.

    Parameters
    ----------
    pretty : bool, optional
        Whether to pretty-print the response.
    wait_for_complete : bool, optional
        Whether to wait for the operation to complete.

    Returns
    -------
    ConnexionResponse
        API response with the operation result.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=content_framework.validate_contents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return json_response(data, pretty=pretty)

async def log_test(pretty: bool = False, wait_for_complete: bool = False):
    """
    Run log test for content files.

    Parameters
    ----------
    pretty : bool, optional
        Whether to pretty-print the response.
    wait_for_complete : bool, optional
        Whether to wait for the operation to complete.

    Returns
    -------
    ConnexionResponse
        API response with the operation result.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=content_framework.log_tests,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return json_response(data, pretty=pretty)