# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.common import database_limit
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_metadata():
    """TODO
    """
    # TODO


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
