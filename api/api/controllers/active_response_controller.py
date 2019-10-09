# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import connexion

import wazuh.active_response as active_response
from api.authentication import get_permissions
from api.models.active_response_model import ActiveResponse
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def run_command(agent_id, pretty=False, wait_for_complete=False):
    """Runs an Active Response command on a specified agent

    :param agent_id: Agent ID. All possible values since 000 onwards
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: message
    """
    # Get body parameters
    active_response_model = ActiveResponse.from_dict(connexion.request.get_json())
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, **{'agent_list': [agent_id]}, **active_response_model.to_dict()}

    dapi = DistributedAPI(f=active_response.run_command,
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
def run_command_all(list_agents=None, pretty=False, wait_for_complete=False):
    """Runs an Active Response command on a specified agent

    :param list_agents: List of agents
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: message
    """
    # Get body parameters
    active_response_model = ActiveResponse.from_dict(connexion.request.get_json())
    func = active_response.run_command_all if list_agents is None else active_response.run_command
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'agent_list': list_agents,  **active_response_model.to_dict()}

    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          broadcasting=list_agents is None
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
