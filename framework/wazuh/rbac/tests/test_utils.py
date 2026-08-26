# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest
from cachetools import TTLCache

with patch('api.configuration.security_conf', new={'auth_token_exp_timeout': 900, 'rbac_mode': 'white'}):
    from wazuh.rbac import utils as rbac_utils
    from wazuh.core import common


@pytest.fixture
def reset_generation():
    """Restore the shared generation counter so tests do not leak state into each other."""
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value = 0
    yield
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value = 0


def _make_cached_lookup(cache, backing):
    """Build a token_cache-decorated function reading from `backing`, mimicking one process."""

    @rbac_utils.token_cache(cache=cache)
    def lookup(username):
        return backing[username]

    return lookup


def test_clear_tokens_cache_bumps_generation(reset_generation):
    """clear_tokens_cache advances the shared counter instead of setting a one-shot flag."""
    start = common.token_cache_generation.value
    rbac_utils.clear_tokens_cache()
    rbac_utils.clear_tokens_cache()
    assert common.token_cache_generation.value == start + 2


def test_single_process_invalidation(reset_generation):
    """A cached decision is dropped after an invalidation and recomputed from source."""
    cache = TTLCache(maxsize=10, ttl=900)
    backing = {'alice': {'valid': True}}
    lookup = _make_cached_lookup(cache, backing)

    assert lookup(username='alice', origin_node_type='master') == {'valid': True}

    # Account removed and cache invalidated: the stale "valid" entry must not survive.
    backing['alice'] = {'valid': False}
    rbac_utils.clear_tokens_cache()

    assert lookup(username='alice', origin_node_type='master') == {'valid': False}


def test_invalidation_reaches_every_process(reset_generation):
    """Regression for the lost-wakeup: one invalidation must flush every process's cache.

    Two independently decorated functions, each with its own cache and its own closure-local
    applied-generation, stand in for two worker processes. Under the previous one-shot
    multiprocessing.Event the first reader consumed the signal and the second kept serving a
    stale decision until the TTL (the token lifetime) expired. Both must now flush.
    """
    backing_a = {'alice': {'valid': True}}
    backing_b = {'alice': {'valid': True}}
    cache_a = TTLCache(maxsize=10, ttl=900)
    cache_b = TTLCache(maxsize=10, ttl=900)
    lookup_a = _make_cached_lookup(cache_a, backing_a)
    lookup_b = _make_cached_lookup(cache_b, backing_b)

    # Warm both process caches with the "valid" decision.
    assert lookup_a(username='alice', origin_node_type='master') == {'valid': True}
    assert lookup_b(username='alice', origin_node_type='master') == {'valid': True}

    # Delete the account and invalidate once, from a third context (e.g. the process pool worker).
    backing_a['alice'] = {'valid': False}
    backing_b['alice'] = {'valid': False}
    rbac_utils.clear_tokens_cache()

    # The first reader flushing must NOT stop the second reader from flushing.
    assert lookup_a(username='alice', origin_node_type='master') == {'valid': False}
    assert lookup_b(username='alice', origin_node_type='master') == {'valid': False}


def test_worker_node_bypasses_cache(reset_generation):
    """Requests whose origin node is not the master are never served from cache."""
    calls = []
    cache = TTLCache(maxsize=10, ttl=900)

    @rbac_utils.token_cache(cache=cache)
    def lookup(username):
        calls.append(username)
        return {'valid': True}

    lookup(username='alice', origin_node_type='worker')
    lookup(username='alice', origin_node_type='worker')

    assert calls == ['alice', 'alice']
    assert len(cache) == 0
