# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict
from wazuh import engine
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from api.models.base_model_ import Body
from api.models.engine_model import AddCatalogResourceModel, UpdateCatalogResourceModel

logger = logging.getLogger('wazuh-api')

# @expose_resources(actions=["engine:add_resource"], resources=["engine:catalog:*"])
async def add_catalog_resource(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Add a resource to the engine catalog.

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
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await AddCatalogResourceModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine.add_catalog_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

# @expose_resources(actions=["engine:get_resource"], resources=["engine:catalog:*"])
async def get_catalog_resource(request, pretty: bool = False, wait_for_complete: bool = False,
                             name: str = None, resource_type: str = None) -> web.Response:
    """Get a resource from the engine catalog.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    name : str
        Resource name.
    resource_type : str
        Resource format type (json, yaml, etc).

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'name': name, 'resource_type': resource_type}

    dapi = DistributedAPI(f=engine.get_catalog_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

# @expose_resources(actions=["engine:update_resource"], resources=["engine:catalog:*"])
async def update_catalog_resource(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Update a resource from the engine catalog.

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
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await UpdateCatalogResourceModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine.update_catalog_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

# @expose_resources(actions=["engine:delete_resource"], resources=["engine:catalog:*"])
async def delete_catalog_resource(request, pretty: bool = False, wait_for_complete: bool = False,
                             name: str = None) -> web.Response:
    """Delete a resource from the engine catalog.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    name : str
        Resource name.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'name': name}

    dapi = DistributedAPI(f=engine.delete_catalog_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

# @expose_resources(actions=["engine:validate_resource"], resources=["engine:catalog:*"])
async def validate_catalog_resource(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Validate the contents of an engine catalog resource.

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
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await UpdateCatalogResourceModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine.validate_catalog_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
