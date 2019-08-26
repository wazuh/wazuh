# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import asyncio
import connexion
import datetime
import logging

from wazuh.agent import Agent as Agent
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh import common
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_agents_summary(pretty=False, wait_for_complete=False):
    """Get full summary of agents.

    Returns a full summary of agents

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Dict with a full summary of agents
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=Agent.get_full_summary,
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
