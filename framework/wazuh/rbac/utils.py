# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
from functools import wraps

from cachetools import TTLCache
from cachetools.keys import hashkey
from wazuh.core.common import cache_event
from wazuh.core.config.client import CentralizedConfig

# Tokens cache
tokens_cache = TTLCache(maxsize=4500, ttl=CentralizedConfig.get_management_api_config().jwt_expiration_timeout)


def clear_cache():
    """Clear the authorization tokens cache."""
    cache_event.set()


def token_cache(cache: TTLCache):
    """Apply cache depending on whether the request comes from the master node or from a worker node.

    Parameters
    ----------
    cache : TTLCache
        Cache object.

    Returns
    -------
    Requested function
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if cache_event.is_set():
                cache.clear()
                cache_event.clear()

            async def f(*_args, **_kwargs):
                k = hashkey(*_args, **_kwargs)
                with contextlib.suppress(KeyError):  # Key not found
                    return cache[k]

                v = await func(*args, **kwargs)

                with contextlib.suppress(ValueError):  # Value too large
                    cache[k] = v

                return v

            return await f(*args, **kwargs)

        return wrapper

    return decorator
