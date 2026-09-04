# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from cachetools import TTLCache

from wazuh.core import common
from wazuh.rbac import utils as rbac_utils


@pytest.fixture
def reset_generation():
    """Restore the shared generation counter so tests do not leak state into each other."""
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value = 0
    yield
    with common.token_cache_generation.get_lock():
        common.token_cache_generation.value = 0


def _make_cached_lookup(cache, backing):
    """Build a policies_cache-decorated function reading from `backing`, mimicking one process."""

    @rbac_utils.policies_cache(cache=cache)
    def lookup(username):
        return backing[username]

    return lookup


def test_policies_cache_ttl_is_bounded():
    """The TTL must not be the token lifetime, so a missed invalidation is always recovered from."""
    assert rbac_utils.POLICIES_CACHE.ttl == rbac_utils.POLICIES_CACHE_TTL
    assert rbac_utils.POLICIES_CACHE_TTL <= 60


def test_clear_tokens_cache_bumps_generation(reset_generation):
    """clear_tokens_cache advances the shared counter instead of setting a one-shot flag."""
    start = common.token_cache_generation.value
    rbac_utils.clear_tokens_cache()
    rbac_utils.clear_tokens_cache()
    assert common.token_cache_generation.value == start + 2


def test_single_process_invalidation(reset_generation):
    """A cached entry is dropped after an invalidation and recomputed from source."""
    cache = TTLCache(maxsize=10, ttl=900)
    backing = {'alice': {'policy': 'old'}}
    lookup = _make_cached_lookup(cache, backing)

    assert lookup(username='alice', origin_node_type='master') == {'policy': 'old'}

    backing['alice'] = {'policy': 'new'}
    rbac_utils.clear_tokens_cache()

    assert lookup(username='alice', origin_node_type='master') == {'policy': 'new'}


def test_invalidation_reaches_every_process(reset_generation):
    """Regression for the lost-wakeup: one invalidation must flush every process's cache.

    Two independently decorated functions, each with its own cache and its own closure-local
    applied-generation, stand in for two authentication workers. Under the previous one-shot
    multiprocessing.Event the first reader consumed the signal and the second kept serving its
    stale entry until the TTL (the token lifetime) expired. Both must now flush.
    """
    backing_a = {'alice': {'policy': 'old'}}
    backing_b = {'alice': {'policy': 'old'}}
    cache_a = TTLCache(maxsize=10, ttl=900)
    cache_b = TTLCache(maxsize=10, ttl=900)
    lookup_a = _make_cached_lookup(cache_a, backing_a)
    lookup_b = _make_cached_lookup(cache_b, backing_b)

    # Warm both process caches.
    assert lookup_a(username='alice', origin_node_type='master') == {'policy': 'old'}
    assert lookup_b(username='alice', origin_node_type='master') == {'policy': 'old'}

    # Invalidate once, from a third context (e.g. the process pool worker handling the revocation).
    backing_a['alice'] = {'policy': 'new'}
    backing_b['alice'] = {'policy': 'new'}
    rbac_utils.clear_tokens_cache()

    # The first reader flushing must NOT stop the second reader from flushing.
    assert lookup_a(username='alice', origin_node_type='master') == {'policy': 'new'}
    assert lookup_b(username='alice', origin_node_type='master') == {'policy': 'new'}


def test_worker_node_bypasses_cache(reset_generation):
    """Requests whose origin node is not the master are never served from cache."""
    calls = []
    cache = TTLCache(maxsize=10, ttl=900)

    @rbac_utils.policies_cache(cache=cache)
    def lookup(username):
        calls.append(username)
        return {'valid': True}

    lookup(username='alice', origin_node_type='worker')
    lookup(username='alice', origin_node_type='worker')

    assert calls == ['alice', 'alice']
    assert len(cache) == 0
