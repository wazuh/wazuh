# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.mitre import mitre_metadata

logger = logging.getLogger('wazuh-api')


async def get_metadata(request, pretty=False, wait_for_complete=False):
    """Return the metadata of the MITRE's database

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Metadata of MITRE's db
    """

    dapi = DistributedAPI(f=mitre_metadata,
                          f_kwargs={},
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_tactics():
    """TODO
    """
    # TODO


async def get_techniques():
    """TODO
    """
    # TODO


async def get_mitigations():
    """TODO
    """
    # TODO


async def get_groups():
    """TODO
    """
    # TODO


async def get_software():
    """TODO
    """
    # TODO
