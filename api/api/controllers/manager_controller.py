# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion.lifecycle import ConnexionResponse

import wazuh.manager as manager
from api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from api.controllers.util import json_response
from api.util import only_master_endpoint, raise_if_exc
from api.signals import cti_context
from wazuh.core import configuration
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.manager import query_update_check_service

logger = logging.getLogger('wazuh-api')


@only_master_endpoint
async def check_available_version(pretty: bool = False, force_query: bool = False) -> ConnexionResponse:
    """Get available update information.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format, by default False.
    force_query : bool, optional
        Make the query to the CTI service on demand, by default False.

    Returns
    -------
    web.Response
        API response.
    """
    installation_uid = cti_context[INSTALLATION_UID_KEY]

    if force_query and configuration.update_check_is_enabled():
        logger.debug('Forcing query to the update check service...')
        dapi = DistributedAPI(f=query_update_check_service,
                              f_kwargs={
                                  INSTALLATION_UID_KEY: installation_uid
                              },
                              request_type='local_master',
                              is_async=True,
                              logger=logger
                              )
        update_information = raise_if_exc(await dapi.distribute_function())
        cti_context[UPDATE_INFORMATION_KEY] = update_information.dikt

    dapi = DistributedAPI(f=manager.get_update_information,
                          f_kwargs={
                              INSTALLATION_UID_KEY: installation_uid,
                              UPDATE_INFORMATION_KEY: cti_context.get(UPDATE_INFORMATION_KEY, {})
                          },
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())
    return json_response(data, pretty=pretty)
