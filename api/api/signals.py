# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import contextlib
import logging
import os
from functools import wraps
from typing import Callable

from connexion import ConnexionMiddleware
from asyncinotify import Inotify, Mask

from api import configuration
from api.constants import (SECURITY_PATH)
from api.authentication import generate_keypair, _private_key_path, _public_key_path

logger = logging.getLogger('wazuh-api')

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
async def clean_auth_keys_cache():
    """Watch for changes in authentication key files and clear the cache of generated keys."""

    FILES = {_private_key_path, _public_key_path}

    with Inotify() as inotify:
        inotify.add_watch(SECURITY_PATH, Mask.MODIFY | Mask.CREATE )
        async for event in inotify:
            if event.path and event.path.as_posix() in FILES:
                generate_keypair.cache_clear()


@contextlib.asynccontextmanager
async def lifespan_handler(_: ConnexionMiddleware):
    """Logs the API startup/shutdown messages and register background tasks."""

    tasks: list[asyncio.Task] = []
    tasks.append(asyncio.create_task(clean_auth_keys_cache()))

    # Log the initial server startup message.
    logger.info(f'Listening on {configuration.api_conf["host"]}:{configuration.api_conf["port"]}.')

    yield

    for task in tasks:
        task.cancel()
        await task

    logger.info('Shutdown wazuh-manager-apid server.')
