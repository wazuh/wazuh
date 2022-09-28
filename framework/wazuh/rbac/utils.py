# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from functools import wraps

from cachetools import TTLCache, cached
from wazuh.core.common import cache_event

from api.configuration import security_conf

# Tokens cache
tokens_cache = TTLCache(maxsize=4500, ttl=security_conf['auth_token_exp_timeout'])


def clear_cache():
    """This function clear the authorization tokens cache."""
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
        def wrapper(*args, **kwargs):
            origin_node_type = kwargs.pop('origin_node_type')

            if cache_event.is_set():
                cache.clear()
                cache_event.clear()

            @cached(cache=cache)
            def f(*_args, **_kwargs):
                return func(*_args, **_kwargs)

            if origin_node_type == 'master':
                return f(*args, **kwargs)

            return func(*args, **kwargs)
        return wrapper
    return decorator
