# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from cachetools import TTLCache, cached
from cachetools.keys import hashkey
from functools import partial, wraps
from os import walk

from wazuh.core import common

from api.configuration import security_conf

tokens_cache = TTLCache(maxsize=4500, ttl=security_conf["auth_token_exp_timeout"])
resources_cache = TTLCache(maxsize=100, ttl=10)


def clear_tokens_cache():
    """This function clear the authorization tokens cache."""
    common.token_cache_event.set()


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
            origin_node_type = kwargs.pop("origin_node_type")

            if common.token_cache_event.is_set():
                cache.clear()
                common.token_cache_event.clear()

            @cached(cache=cache)
            def f(*_args, **_kwargs):
                return func(*_args, **_kwargs)

            if origin_node_type == "master":
                return f(*args, **kwargs)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def resource_cache(cache: TTLCache):
    """Apply cache depending on the function type.

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


@resource_cache(cache=resources_cache)
def expand_rules() -> set:
    """Return all ruleset rule files in the system.

    Returns
    -------
    set
        Rule files.
    """
    folders = [common.RULES_PATH, common.USER_RULES_PATH]
    rules = set()
    for folder in folders:
        for _, _, files in walk(folder):
            for f in filter(lambda x: x.endswith(common.RULES_EXTENSION), files):
                rules.add(f)

    return rules


@resource_cache(cache=resources_cache)
def expand_decoders() -> set:
    """Return all ruleset decoder files in the system.

    Returns
    -------
    set
        Decoder files.
    """
    folders = [common.DECODERS_PATH, common.USER_DECODERS_PATH]
    decoders = set()
    for folder in folders:
        for _, _, files in walk(folder):
            for f in filter(lambda x: x.endswith(common.DECODERS_EXTENSION), files):
                decoders.add(f)

    return decoders


@resource_cache(cache=resources_cache)
def expand_lists() -> set:
    """Return all cdb list files in the system.

    Returns
    -------
    set
        CDB list files.
    """
    folders = [common.LISTS_PATH, common.USER_LISTS_PATH]
    lists = set()
    for folder in folders:
        for _, _, files in walk(folder):
            for f in filter(lambda x: x.endswith(common.LISTS_EXTENSION), files):
                # List files do not have an extension at the moment
                if "." not in f:
                    lists.add(f)

    return lists
