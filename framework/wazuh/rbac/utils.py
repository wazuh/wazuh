# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from cachetools import TTLCache, cached
from cachetools.keys import hashkey
from functools import partial, wraps

from wazuh.core import common

# Maximum staleness of a cached RBAC policy set, in seconds.
#
# This is deliberately NOT derived from `auth_token_exp_timeout` any more. Tying it to the token
# lifetime meant that an invalidation which failed to reach a process was never recovered from
# before the token expired anyway, which is what turned a cache-coherency defect into a
# full-window authentication bypass. A short fixed TTL bounds the damage of any future miss.
POLICIES_CACHE_TTL = 30

# RBAC policies granted by a set of roles. This cache holds only the result of the policy
# preprocessing, never an authentication or revocation decision: `check_token` re-reads the
# account, its roles and the token blacklist from the database on every request, so a hit here
# can never keep a deleted, blacklisted or re-roled user authenticated.
POLICIES_CACHE = TTLCache(maxsize=4500, ttl=POLICIES_CACHE_TTL)
RESOURCES_CACHE = TTLCache(maxsize=100, ttl=10)


def clear_tokens_cache():
    """Invalidate the RBAC policies cache in every process of the caller's process tree.

    Called from the token revocation paths (`TokenManager.add_user_roles_rules` and
    `TokenManager.delete_all_rules`), since a revocation may also have changed which policies a
    role grants.

    Bumps the shared generation counter so that every process flushes its own copy of the cache on
    its next cached call, rather than relying on a one-shot flag that only one process consumes.

    The counter is a `multiprocessing.Value`, so it only reaches the process tree that created it:
    in practice the API's own pools, which are forked from it. A mutation executed elsewhere -- an
    RBAC change forwarded from a worker node runs inside `wazuh-clusterd` -- bumps that tree's
    counter instead, and the API only picks the change up when `POLICIES_CACHE_TTL` expires. That
    is a freshness bound, not a security one: `check_token` re-reads the account, its roles and the
    token blacklist on every request, so no stale identity is ever served.
    """
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value += 1


def policies_cache(cache: TTLCache = POLICIES_CACHE):
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

            # `Synchronized.value` acquires the shared lock on read, exactly as the `Event.is_set()`
            # it replaces did, so this costs no more per request. The counter only ever grows, so a
            # read that races with a bump merely defers the flush to the next call.
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
