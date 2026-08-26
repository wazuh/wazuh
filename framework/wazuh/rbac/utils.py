# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from cachetools import TTLCache, cached
from cachetools.keys import hashkey
from functools import partial, wraps

from wazuh.core import common

from api.configuration import security_conf

TOKENS_CACHE = TTLCache(maxsize=4500, ttl=security_conf['auth_token_exp_timeout'])
RESOURCES_CACHE = TTLCache(maxsize=100, ttl=10)


def clear_tokens_cache():
    """Invalidate the authorization tokens cache in every process.

    Bumps the shared generation counter so each process flushes its own copy of the cache on
    its next cached call, rather than relying on a one-shot flag that only one process consumes.
    """
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value += 1


def token_cache(cache: TTLCache = TOKENS_CACHE):
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
        # Last invalidation generation this process has already applied to `cache`. It lives in the
        # closure so it is per decorated function and per process, matching the per-process cache.
        applied_generation = 0

        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal applied_generation
            origin_node_type = kwargs.pop('origin_node_type')

            # Reading .value takes the shared lock, as the previous Event.is_set() did, so this
            # adds no per-request cost over the mechanism it replaces. The counter only ever grows.
            current_generation = common.token_cache_generation.value
            if current_generation != applied_generation:
                cache.clear()
                applied_generation = current_generation

            @cached(cache=cache)
            def f(*_args, **_kwargs):
                return func(*_args, **_kwargs)

            if origin_node_type == 'master':
                return f(*args, **kwargs)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def resource_cache(cache: TTLCache = RESOURCES_CACHE):
    """Apply cache depending on the decorated function name.

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
        def wrapper(*args, **kwargs):

            # Use different keys for each function to avoid collisions
            @cached(cache=cache, key=partial(hashkey, func.__name__))
            def f(*_args, **_kwargs):
                return func(*_args, **_kwargs)

            return f(*args, **kwargs)

        return wrapper

    return decorator
