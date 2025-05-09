# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import contextlib
import logging
import os
import uuid
from functools import wraps
from typing import Callable

from connexion import ConnexionMiddleware
from wazuh.core import common
from wazuh.core.common import get_installation_uid
from wazuh.core.cluster.utils import running_in_master_node
from wazuh.core.configuration import update_check_is_enabled
from wazuh.core.manager import query_update_check_service

from api import configuration
from api.constants import (
    INSTALLATION_UID_KEY,
    INSTALLATION_UID_PATH,
    UPDATE_INFORMATION_KEY,
)

ONE_DAY_SLEEP = 60*60*24

logger = logging.getLogger('wazuh-api')

cti_context = {}


def cancel_signal_handler(func: Callable) -> Callable:
    """Decorator to handle asyncio.CancelledError for signals coroutines.

    Parameters
    ----------
    func : Callable
        Coroutine to handle.

    Returns
    -------
    Callable
        Wrapped coroutine with exception handled.
    """

    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            await func(*args, **kwargs)
        except asyncio.CancelledError:
            pass
    return wrapper


@cancel_signal_handler
async def load_installation_uid() -> None:
    """Load the installation UID into the global cti context."""
    global cti_context

    if os.path.exists(INSTALLATION_UID_PATH):
        logger.info("Getting installation UID...")
    else:
        logger.info("Populating installation UID...")

    cti_context[INSTALLATION_UID_KEY] = get_installation_uid()


@cancel_signal_handler
async def get_update_information() -> None:
    """Get updates information from Update Check Service and inject into the global cti context."""

    global cti_context
    while True:
        logger.info('Getting updates information...')
        cti_context[UPDATE_INFORMATION_KEY] = await query_update_check_service(cti_context[INSTALLATION_UID_KEY])
        await asyncio.sleep(ONE_DAY_SLEEP)


@contextlib.asynccontextmanager
async def lifespan_handler(_: ConnexionMiddleware):
    """Logs the API startup/shutdown messages and register background tasks."""

    tasks: list[asyncio.Task] = []

    if running_in_master_node():
        tasks.append(asyncio.create_task(load_installation_uid()))
        if update_check_is_enabled():
            tasks.append(asyncio.create_task(get_update_information()))

    # Log the initial server startup message.
    logger.info(f'Listening on {configuration.api_conf["host"]}:{configuration.api_conf["port"]}.')

    yield

    for task in tasks:
        task.cancel()
        await task

    logger.info('Shutdown wazuh-apid server.')
