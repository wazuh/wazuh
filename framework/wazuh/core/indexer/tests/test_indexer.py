# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import AsyncMock, MagicMock, patch, call
import ssl
from datetime import datetime, timedelta

import pytest

from wazuh.core.indexer.indexer import (
    get_indexer_client,
    resolve_wazuh_path,
    _get_cached_indexer_config,
    _create_ssl_context,
    _IndexerCircuitBreaker,
)
from wazuh.core.exception import IndexerUnavailableError


def test_resolve_wazuh_path_keeps_absolute_paths():
    path = "/tmp/root-ca.pem"

    assert resolve_wazuh_path(path) == path


def test_resolve_wazuh_path_uses_wazuh_path_for_relative_paths():
    with patch("wazuh.core.indexer.indexer.common.WAZUH_PATH", "/var/wazuh-manager"):
        assert (
            resolve_wazuh_path("etc/certs/root-ca.pem")
            == "/var/wazuh-manager/etc/certs/root-ca.pem"
        )


@pytest.mark.asyncio
async def test_get_indexer_client_resolves_relative_certificate_paths():
    client = AsyncMock()
    client.close = AsyncMock()
    keystore_client = MagicMock()
    keystore_client.__enter__.return_value.get.side_effect = [
        {"value": "wazuh-manager"},
        {"value": "wazuh-manager"},
    ]

    wazuh_config = {
        "indexer": {
            "hosts": ["https://localhost:9200"],
            "ssl": {
                "certificate_authorities": [{"ca": ["etc/certs/root-ca.pem"]}],
                "certificate": ["etc/certs/indexer-connector.pem"],
                "key": ["etc/certs/indexer-connector-key.pem"],
            },
        }
    }

    mock_ssl_context = MagicMock(spec=ssl.SSLContext)

    with patch("wazuh.core.indexer.indexer.common.WAZUH_PATH", "/var/wazuh-manager"), \
            patch(
                "wazuh.core.indexer.indexer._get_cached_indexer_config",
                new_callable=AsyncMock,
                return_value=wazuh_config,
            ), \
            patch(
                "wazuh.core.indexer.indexer.KeystoreClient",
                return_value=keystore_client,
            ), \
            patch(
                "wazuh.core.indexer.indexer._create_ssl_context",
                return_value=mock_ssl_context,
            ) as create_ssl_context, \
            patch(
                "wazuh.core.indexer.indexer.create_indexer",
                new_callable=AsyncMock,
                return_value=client,
            ) as create_indexer, \
            patch(
                "wazuh.core.indexer.indexer._IndexerCircuitBreaker.check",
                new_callable=AsyncMock,
            ):
        async with get_indexer_client():
            pass

    # Verify SSL context was created with resolved paths
    create_ssl_context.assert_called_once_with(
        "/var/wazuh-manager/etc/certs/indexer-connector.pem",
        "/var/wazuh-manager/etc/certs/indexer-connector-key.pem",
        "/var/wazuh-manager/etc/certs/root-ca.pem",
    )

    # Verify indexer was created with SSL context instead of cert paths
    create_indexer.assert_awaited_once_with(
        hosts=["localhost"],
        ports=[9200],
        user="wazuh-manager",
        password="wazuh-manager",
        use_ssl=True,
        ssl_context=mock_ssl_context,
    )
    client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_cached_indexer_config_caches_result():
    """Test that config is cached and not re-read on subsequent calls."""
    config = {"indexer": {"hosts": ["localhost:9200"]}}

    with patch("wazuh.core.indexer.indexer.get_ossec_conf", return_value=config) as mock_get_conf, \
         patch("wazuh.core.indexer.indexer.os.path.getmtime", return_value=123456.0):
        # First call - should read config
        result1 = await _get_cached_indexer_config()
        assert result1 == config
        assert mock_get_conf.call_count == 1

        # Second call - should use cache
        result2 = await _get_cached_indexer_config()
        assert result2 == config
        assert mock_get_conf.call_count == 1  # Still only called once


@pytest.mark.asyncio
async def test_get_cached_indexer_config_invalidates_on_file_change():
    """Test that cache is invalidated when config file mtime changes."""
    import wazuh.core.indexer.indexer as indexer_module

    # Clear cache first
    indexer_module._config_cache = None
    indexer_module._config_mtime = None

    config1 = {"indexer": {"hosts": ["localhost:9200"]}}
    config2 = {"indexer": {"hosts": ["localhost:9201"]}}

    with patch("wazuh.core.indexer.indexer.get_ossec_conf", side_effect=[config1, config2]) as mock_get_conf, \
         patch("wazuh.core.indexer.indexer.os.path.getmtime", side_effect=[123456.0, 789012.0]):
        # First call
        result1 = await _get_cached_indexer_config()
        assert result1 == config1

        # Second call with different mtime - should re-read
        result2 = await _get_cached_indexer_config()
        assert result2 == config2
        assert mock_get_conf.call_count == 2


def test_create_ssl_context_caching():
    """Test that SSL context is cached with double-checked locking."""
    import wazuh.core.indexer.indexer as indexer_module

    cert = "/path/cert.pem"
    key = "/path/key.pem"
    ca = "/path/ca.pem"

    # Clear the cache first
    indexer_module._ssl_context_cache = None
    indexer_module._ssl_context_cache_key = None

    with patch("wazuh.core.indexer.indexer.ssl.create_default_context") as mock_create:
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_create.return_value = mock_context

        # First call
        result1 = _create_ssl_context(cert, key, ca)
        assert mock_create.call_count == 1

        # Second call with same params - should use cache
        result2 = _create_ssl_context(cert, key, ca)
        assert result1 is result2
        assert mock_create.call_count == 1  # Still only called once

        # Clear cache and try different params - should create new context
        indexer_module._ssl_context_cache = None
        indexer_module._ssl_context_cache_key = None
        result3 = _create_ssl_context("/other/cert.pem", key, ca)
        assert mock_create.call_count == 2


@pytest.mark.asyncio
async def test_circuit_breaker_allows_connection_when_closed():
    """Test that circuit breaker allows connections when closed."""
    # Reset circuit breaker
    _IndexerCircuitBreaker._open_until = None

    # Should not raise
    await _IndexerCircuitBreaker.check()


@pytest.mark.asyncio
async def test_circuit_breaker_blocks_connection_when_open():
    """Test that circuit breaker blocks connections when open."""
    # Open the circuit breaker
    await _IndexerCircuitBreaker.record_failure()

    # Should raise IndexerUnavailableError
    with pytest.raises(IndexerUnavailableError, match="Circuit breaker open"):
        await _IndexerCircuitBreaker.check()

    # Reset for other tests
    _IndexerCircuitBreaker._open_until = None


@pytest.mark.asyncio
async def test_circuit_breaker_closes_on_success():
    """Test that circuit breaker closes after successful connection."""
    # Open the circuit breaker
    await _IndexerCircuitBreaker.record_failure()
    assert _IndexerCircuitBreaker._open_until is not None

    # Record success
    await _IndexerCircuitBreaker.record_success()
    assert _IndexerCircuitBreaker._open_until is None

    # Should now allow connections
    await _IndexerCircuitBreaker.check()


@pytest.mark.asyncio
async def test_circuit_breaker_reopens_after_timeout():
    """Test that circuit breaker allows retry after timeout period."""
    # Open the circuit breaker with past timestamp
    past_time = datetime.now() - timedelta(seconds=10)
    _IndexerCircuitBreaker._open_until = past_time

    # Should allow connection (timeout expired)
    await _IndexerCircuitBreaker.check()

    # Reset
    _IndexerCircuitBreaker._open_until = None


@pytest.mark.asyncio
async def test_get_indexer_client_raises_when_circuit_breaker_open():
    """Test that get_indexer_client respects circuit breaker."""
    # Open circuit breaker
    await _IndexerCircuitBreaker.record_failure()

    try:
        with pytest.raises(IndexerUnavailableError, match="Circuit breaker open"):
            async with get_indexer_client():
                pass
    finally:
        # Reset for other tests
        _IndexerCircuitBreaker._open_until = None
