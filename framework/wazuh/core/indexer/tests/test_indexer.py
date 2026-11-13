# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import AsyncMock, MagicMock, patch, call
import json
import os
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

# The frozen effective document test_configuration.py's test_get_manager_conf() checks
# against: schema defaults applied to a <indexer> with no <ssl> block at all. Reading
# indexer.ssl from here instead of hand-typing it keeps this test tied to whatever the
# config loader actually produces, so a shape change here fails visibly instead of
# silently matching a stale literal.
EFFECTIVE_CONFIG_FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "data", "configuration", "wazuh-manager.effective.json"
)


def _load_effective_indexer_ssl():
    with open(EFFECTIVE_CONFIG_FIXTURE) as f:
        return json.load(f)["indexer"]["ssl"]


def test_resolve_wazuh_path_keeps_absolute_paths():
    path = "/tmp/indexer-ca.pem"

    assert resolve_wazuh_path(path) == path


def test_resolve_wazuh_path_uses_wazuh_path_for_relative_paths():
    with patch("wazuh.core.indexer.indexer.common.WAZUH_PATH", "/var/wazuh-manager"):
        assert (
            resolve_wazuh_path("etc/certs/indexer-ca.pem")
            == "/var/wazuh-manager/etc/certs/indexer-ca.pem"
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
                "certificate_authorities": ["etc/certs/indexer-ca.pem"],
                "certificate": "etc/certs/indexer-connector.pem",
                "key": "etc/certs/indexer-connector-key.pem",
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
        ["/var/wazuh-manager/etc/certs/indexer-ca.pem"],
        True,
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


async def _run_get_indexer_client(indexer_extra, hosts=("https://localhost:9200",), with_create_indexer=False):
    """Run get_indexer_client() with a given indexer config and return the
    _create_ssl_context mock, so callers can assert what it was called with (and the
    create_indexer mock too when with_create_indexer is set)."""
    client = AsyncMock()
    client.close = AsyncMock()
    keystore_client = MagicMock()
    keystore_client.__enter__.return_value.get.side_effect = [
        {"value": "wazuh-manager"},
        {"value": "wazuh-manager"},
    ]

    wazuh_config = {"indexer": {"hosts": list(hosts), **indexer_extra}}
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

    if with_create_indexer:
        return create_ssl_context, create_indexer
    return create_ssl_context


@pytest.mark.asyncio
@pytest.mark.parametrize("ssl_section", [
    {},
    {"certificate_authorities": ["etc/certs/indexer-ca.pem"]},
    # Invalid for TLS (certificate without key), irrelevant without it.
    {"certificate": "etc/certs/indexer-connector.pem"},
], ids=["no-ssl", "ca-only", "certificate-without-key"])
async def test_get_indexer_client_http_hosts_connect_without_tls(ssl_section):
    """An http:// host means plain HTTP, as for the C++ indexer connector: no TLS context is built
    and indexer.ssl is neither required nor validated."""
    create_ssl_context, create_indexer = await _run_get_indexer_client(
        {"ssl": ssl_section}, hosts=("http://wazuh.indexer:9200",), with_create_indexer=True
    )

    create_ssl_context.assert_not_called()
    create_indexer.assert_awaited_once_with(
        hosts=["wazuh.indexer"],
        ports=[9200],
        user="wazuh-manager",
        password="wazuh-manager",
        use_ssl=False,
        ssl_context=None,
    )


@pytest.mark.asyncio
async def test_get_indexer_client_https_hosts_use_tls():
    create_ssl_context, create_indexer = await _run_get_indexer_client(
        {}, hosts=("https://node1:9200", "HTTPS://node2:9201"), with_create_indexer=True
    )

    create_ssl_context.assert_called_once_with(None, None, [], True)
    kwargs = create_indexer.await_args.kwargs
    assert kwargs["use_ssl"] is True
    assert kwargs["ssl_context"] is create_ssl_context.return_value
    assert (kwargs["hosts"], kwargs["ports"]) == (["node1", "node2"], [9200, 9201])


@pytest.mark.asyncio
async def test_get_indexer_client_refuses_mixed_schemes():
    """The client has one TLS setting for every node: a mixed list is refused, naming the cause."""
    with pytest.raises(IndexerUnavailableError, match="mixes http:// and https://"):
        await _run_get_indexer_client({}, hosts=("https://node1:9200", "http://node2:9200"))


@pytest.mark.asyncio
async def test_get_indexer_client_refuses_an_unknown_scheme():
    with pytest.raises(IndexerUnavailableError, match="Unsupported indexer host scheme: ftp"):
        await _run_get_indexer_client({}, hosts=("ftp://node1:9200",))


@pytest.mark.asyncio
async def test_get_indexer_client_without_ssl_section_has_no_client_cert():
    create_ssl_context = await _run_get_indexer_client({})

    create_ssl_context.assert_called_once_with(None, None, [], True)


@pytest.mark.asyncio
async def test_get_indexer_client_with_empty_ssl_section_has_no_client_cert():
    create_ssl_context = await _run_get_indexer_client({"ssl": {}})

    create_ssl_context.assert_called_once_with(None, None, [], True)


@pytest.mark.asyncio
async def test_get_indexer_client_with_schema_default_ssl_has_no_client_cert():
    """Same as the empty-<ssl> case above, but sourced from the frozen effective-config
    fixture instead of a hand-typed literal (see EFFECTIVE_CONFIG_FIXTURE)."""
    create_ssl_context = await _run_get_indexer_client({"ssl": _load_effective_indexer_ssl()})

    create_ssl_context.assert_called_once_with(None, None, [], True)


@pytest.mark.asyncio
async def test_get_indexer_client_with_only_certificate_authorities_has_no_client_cert():
    create_ssl_context = await _run_get_indexer_client(
        {"ssl": {"certificate_authorities": ["etc/certs/indexer-ca.pem"]}}
    )

    create_ssl_context.assert_called_once_with(
        None, None, ["/var/wazuh-manager/etc/certs/indexer-ca.pem"], True
    )


@pytest.mark.asyncio
async def test_get_indexer_client_resolves_every_configured_certificate_authority():
    create_ssl_context = await _run_get_indexer_client(
        {
            "ssl": {
                "certificate_authorities": [
                    "etc/certs/old-ca.pem",
                    "etc/certs/new-ca.pem",
                ]
            }
        }
    )

    create_ssl_context.assert_called_once_with(
        None,
        None,
        [
            "/var/wazuh-manager/etc/certs/old-ca.pem",
            "/var/wazuh-manager/etc/certs/new-ca.pem",
        ],
        True,
    )


@pytest.mark.asyncio
async def test_get_indexer_client_raises_when_certificate_set_without_key():
    with pytest.raises(IndexerUnavailableError, match="must be set together"):
        await _run_get_indexer_client(
            {"ssl": {"certificate": "etc/certs/indexer-connector.pem"}}
        )


@pytest.mark.asyncio
async def test_get_indexer_client_raises_on_a_lone_empty_certificate_authority():
    """A single blank <ca></ca> entry can never resolve to a usable file, so it is
    rejected instead of silently treated as "no CA configured" (that case is an empty
    list, not a list holding one empty string)."""
    with pytest.raises(IndexerUnavailableError, match="must not contain empty entries"):
        await _run_get_indexer_client({"ssl": {"certificate_authorities": [""]}})


@pytest.mark.asyncio
async def test_get_indexer_client_raises_on_a_mixed_empty_certificate_authority():
    """Same as above, but mixed in with an otherwise valid CA -- the valid entry must
    not mask the blank one."""
    with pytest.raises(IndexerUnavailableError, match="must not contain empty entries"):
        await _run_get_indexer_client(
            {"ssl": {"certificate_authorities": ["etc/certs/indexer-ca.pem", ""]}}
        )


@pytest.mark.asyncio
async def test_get_indexer_client_wraps_ssl_context_errors():
    """A bad certificate path must not escape as a raw FileNotFoundError -- it should be
    wrapped in IndexerUnavailableError so the log names the actual problem instead of the
    generic "Indexer is not configured or unavailable" manage_indexer_tasks() falls back to."""
    import wazuh.core.indexer.indexer as indexer_module

    indexer_module._ssl_context_cache = None
    indexer_module._ssl_context_cache_key = None

    client = AsyncMock()
    keystore_client = MagicMock()
    keystore_client.__enter__.return_value.get.side_effect = [
        {"value": "wazuh-manager"},
        {"value": "wazuh-manager"},
    ]

    wazuh_config = {
        "indexer": {
            "hosts": ["https://localhost:9200"],
            "ssl": {
                "certificate": "/nonexistent/typo.pem",
                "key": "/nonexistent/typo-key.pem",
            },
        }
    }

    with patch(
                "wazuh.core.indexer.indexer._get_cached_indexer_config",
                new_callable=AsyncMock,
                return_value=wazuh_config,
            ), \
            patch(
                "wazuh.core.indexer.indexer.KeystoreClient",
                return_value=keystore_client,
            ), \
            patch(
                "wazuh.core.indexer.indexer.create_indexer",
                new_callable=AsyncMock,
                return_value=client,
            ), \
            patch(
                "wazuh.core.indexer.indexer._IndexerCircuitBreaker.check",
                new_callable=AsyncMock,
            ):
        with pytest.raises(IndexerUnavailableError, match="Failed to build SSL context"):
            async with get_indexer_client():
                pass


@pytest.mark.asyncio
async def test_get_cached_indexer_config_caches_result():
    """Test that config is cached and not re-read on subsequent calls."""
    config = {"indexer": {"hosts": ["localhost:9200"]}}

    with patch("wazuh.core.indexer.indexer.get_manager_conf", return_value=config) as mock_get_conf, \
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

    with patch("wazuh.core.indexer.indexer.get_manager_conf", side_effect=[config1, config2]) as mock_get_conf, \
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
    ca = ["/path/ca.pem"]

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


def test_create_ssl_context_trusts_every_configured_certificate_authority():
    """Every CA in the list must end up trusted, not just the first one."""
    import wazuh.core.indexer.indexer as indexer_module

    indexer_module._ssl_context_cache = None
    indexer_module._ssl_context_cache_key = None

    with patch("wazuh.core.indexer.indexer.ssl.create_default_context") as mock_create:
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_create.return_value = mock_context

        _create_ssl_context(None, None, ["/path/old-ca.pem", "/path/new-ca.pem"])

        # The first CA is loaded exclusively (no system trust store fallback)...
        mock_create.assert_called_once_with(
            purpose=ssl.Purpose.SERVER_AUTH, cafile="/path/old-ca.pem"
        )
        # ...and every additional CA is trusted on top of it.
        mock_context.load_verify_locations.assert_called_once_with(cafile="/path/new-ca.pem")


def _reset_ssl_cache():
    import wazuh.core.indexer.indexer as indexer_module

    indexer_module._ssl_context_cache = None
    indexer_module._ssl_context_cache_key = None


class _RecordingContext:
    """Stand-in SSLContext that records the order of attribute assignments."""

    def __init__(self, default_cas=0):
        self.order = []
        self.load_verify_locations = MagicMock()
        self.load_cert_chain = MagicMock()
        self.cert_store_stats = MagicMock(return_value={"x509_ca": default_cas, "crl": 0, "x509": default_cas})

    def __setattr__(self, name, value):
        if name in ("check_hostname", "verify_mode"):
            self.order.append((name, value))
        super().__setattr__(name, value)


@pytest.fixture
def fake_system_cas(tmp_path):
    """Point SYSTEM_CA_PATHS at temporary files; returns (paths, create)."""
    import wazuh.core.indexer.indexer as indexer_module

    paths = [str(tmp_path / f"store{i}.pem") for i in range(5)]
    _reset_ssl_cache()
    with patch.object(indexer_module, "SYSTEM_CA_PATHS", paths):
        yield paths
    _reset_ssl_cache()


@pytest.fixture
def wazuh_log_capture(caplog):
    """Capture the `wazuh` logger's records whatever its propagation: `wazuh.core.wlogging` sets
    `propagate = False` on it when another test configured logging first, and then caplog's root handler
    sees nothing (the same reason `core/tests/test_stats.py` asserts on the module's logger). The handler is
    attached to the logger itself, and propagation is cut while it is, so no record is counted twice."""
    import logging

    logger = logging.getLogger("wazuh")
    old_level, old_propagate = logger.level, logger.propagate
    logger.addHandler(caplog.handler)
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)
        logger.setLevel(old_level)
        logger.propagate = old_propagate


def _warnings(caplog):
    return [r for r in caplog.records if r.levelname == "WARNING" and "certificate verification disabled" in r.getMessage()]


def test_production_system_ca_paths_match_v1():
    import wazuh.core.indexer.indexer as indexer_module

    assert indexer_module.SYSTEM_CA_PATHS == [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/share/ssl/certs/ca-bundle.crt",
        "/usr/local/share/certs/ca-root-nss.crt",
        "/etc/ssl/cert.pem",
    ]


def test_create_ssl_context_configured_ca_beats_system_store(fake_system_cas):
    open(fake_system_cas[0], "w").close()
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context") as mock_create:
        mock_create.return_value = MagicMock(spec=ssl.SSLContext)
        _create_ssl_context(None, None, ["/path/ca.pem"], True)

    mock_create.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH, cafile="/path/ca.pem")


def test_create_ssl_context_first_existing_system_path_wins(fake_system_cas):
    # Paths 0 and 1 absent; 2 and 3 exist: the first existing one is the cafile.
    for p in fake_system_cas[2:4]:
        open(p, "w").close()
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context") as mock_create:
        context = MagicMock(spec=ssl.SSLContext)
        mock_create.return_value = context
        result = _create_ssl_context(None, None, [], True)

    mock_create.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH, cafile=fake_system_cas[2])
    assert result is context
    # Verification stays on: the mock's verify_mode/check_hostname were not touched.
    assert not isinstance(context.verify_mode, ssl.VerifyMode)


def test_create_ssl_context_directory_as_path_component_is_absent(fake_system_cas, tmp_path):
    """NotADirectoryError counts as absent, as FileNotFoundError does."""
    import wazuh.core.indexer.indexer as indexer_module

    regular = tmp_path / "file"
    regular.write_text("x")
    paths = [str(regular / "under-a-file.pem"), fake_system_cas[1]]
    open(fake_system_cas[1], "w").close()
    with patch.object(indexer_module, "SYSTEM_CA_PATHS", paths):
        assert indexer_module._first_existing_system_ca() == fake_system_cas[1]


def test_create_ssl_context_unreadable_system_path_is_chosen_and_fails(fake_system_cas):
    """A path whose stat fails with another error is selected, so building the context
    fails instead of skipping to the next store or disabling verification."""
    import wazuh.core.indexer.indexer as indexer_module

    open(fake_system_cas[1], "w").close()
    real_stat = os.stat

    def fake_stat(path, *a, **k):
        if path == fake_system_cas[0]:
            raise PermissionError(13, "denied")
        return real_stat(path, *a, **k)

    with patch("wazuh.core.indexer.indexer.os.stat", side_effect=fake_stat):
        assert indexer_module._first_existing_system_ca() == fake_system_cas[0]
        with pytest.raises(OSError):
            # The chosen path does not exist on disk, so the real context fails to load it.
            _create_ssl_context(None, None, [], True)


def test_create_ssl_context_broken_system_store_fails_closed(fake_system_cas):
    """The first existing store is garbage: it is chosen, loading fails, and the next
    (valid) store is never tried."""
    with open(fake_system_cas[0], "w") as f:
        f.write("not a certificate")
    open(fake_system_cas[1], "w").close()

    with pytest.raises(ssl.SSLError):
        _create_ssl_context(None, None, [], True)


def _no_trust_warnings(caplog):
    return [r for r in caplog.records if r.levelname == "WARNING" and "no default trust" in r.getMessage()]


def test_create_ssl_context_no_ca_no_store_no_default_trust_fails_closed_with_one_warning(fake_system_cas, caplog, wazuh_log_capture):
    """No CA, none of the 5 system paths and an empty OpenSSL default trust: verification stays
    on (every https connection fails) and one warning says why -- never CERT_NONE."""
    context = _RecordingContext(default_cas=0)
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context", return_value=context) as mock_create, \
            caplog.at_level("WARNING", logger="wazuh"):
        result = _create_ssl_context(None, None, [], True)
        # Cached: a second call neither rebuilds nor warns again.
        assert _create_ssl_context(None, None, [], True) is result

    mock_create.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH, cafile=None)
    assert context.order == []
    assert _warnings(caplog) == []
    warnings = _no_trust_warnings(caplog)
    assert len(warnings) == 1
    assert "indexer.ssl.certificate_authorities" in warnings[0].getMessage()


def test_create_ssl_context_no_ca_no_store_uses_default_trust(fake_system_cas, caplog, wazuh_log_capture):
    """None of the 5 system paths, but OpenSSL's default trust loaded CAs: verify against it."""
    context = _RecordingContext(default_cas=146)
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context", return_value=context) as mock_create, \
            caplog.at_level("WARNING", logger="wazuh"):
        _create_ssl_context(None, None, [], True)

    mock_create.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH, cafile=None)
    assert context.order == []
    assert _warnings(caplog) == [] and _no_trust_warnings(caplog) == []


def test_create_ssl_context_real_context_without_store_keeps_verifying(fake_system_cas):
    context = _create_ssl_context(None, None, [], True)

    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("ca_certs", [[], ["/path/ca.pem"]], ids=["no-ca", "configured-ca"])
def test_create_ssl_context_false_disables_verification(fake_system_cas, caplog, wazuh_log_capture, ca_certs):
    open(fake_system_cas[0], "w").close()
    context = _RecordingContext()
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context", return_value=context) as mock_create, \
            caplog.at_level("WARNING", logger="wazuh"):
        _create_ssl_context("/c.pem", "/k.pem", ca_certs, False)

    # The configured CA (if any) is still loaded; the system store is not consulted.
    mock_create.assert_called_once_with(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_certs[0] if ca_certs else None
    )
    context.load_cert_chain.assert_called_once_with(certfile="/c.pem", keyfile="/k.pem")
    assert context.order == [("check_hostname", False), ("verify_mode", ssl.CERT_NONE)]
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "verify_certificates is false" in warnings[0].getMessage()


def test_create_ssl_context_true_with_ca_does_not_warn(fake_system_cas, caplog, wazuh_log_capture):
    context = _RecordingContext()
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context", return_value=context), \
            caplog.at_level("WARNING", logger="wazuh"):
        _create_ssl_context(None, None, ["/path/ca.pem"], True)

    assert context.order == []
    assert _warnings(caplog) == []


def test_create_ssl_context_real_context_without_verification(fake_system_cas):
    context = _create_ssl_context(None, None, [], False)

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_create_ssl_context_cache_key_includes_verify_certificates(fake_system_cas):
    with patch("wazuh.core.indexer.indexer.ssl.create_default_context") as mock_create:
        mock_create.side_effect = lambda **_: MagicMock(spec=ssl.SSLContext)
        first = _create_ssl_context(None, None, ["/path/ca.pem"], True)
        second = _create_ssl_context(None, None, ["/path/ca.pem"], False)
        assert first is not second
        assert mock_create.call_count == 2
        assert _create_ssl_context(None, None, ["/path/ca.pem"], False) is second
        assert mock_create.call_count == 2


def test_build_ssl_context_false_with_malformed_ca_is_still_error_2200(tmp_path):
    """With verify_certificates false the configured CA is still loaded and validated."""
    from wazuh.core.exception import IndexerConfigurationError
    from wazuh.core.indexer.indexer import _build_ssl_context

    bad_ca = tmp_path / "ca.pem"
    bad_ca.write_text("not a certificate")
    _reset_ssl_cache()

    with pytest.raises(IndexerConfigurationError, match="Failed to build SSL context") as exc:
        _build_ssl_context({"certificate_authorities": [str(bad_ca)], "verify_certificates": False})
    assert exc.value.code == 2200
    _reset_ssl_cache()


@pytest.mark.asyncio
@pytest.mark.parametrize("value,expected", [(False, False), (True, True)])
async def test_get_indexer_client_passes_verify_certificates(value, expected):
    create_ssl_context = await _run_get_indexer_client({"ssl": {"verify_certificates": value}})

    create_ssl_context.assert_called_once_with(None, None, [], expected)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["no", "false", 0, 1, [], None])
async def test_get_indexer_client_rejects_non_boolean_verify_certificates(value):
    with pytest.raises(IndexerUnavailableError, match="verify_certificates must be a boolean"):
        await _run_get_indexer_client({"ssl": {"verify_certificates": value}})


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


@pytest.mark.asyncio
async def test_circuit_breaker_closes_when_the_configuration_changes():
    """A wazuh-manager.conf change may have fixed the failure: the next attempt is let through."""
    with patch("wazuh.core.indexer.indexer.os.path.getmtime", return_value=100.0):
        await _IndexerCircuitBreaker.record_failure()
        with pytest.raises(IndexerUnavailableError, match="Circuit breaker open"):
            await _IndexerCircuitBreaker.check()

    with patch("wazuh.core.indexer.indexer.os.path.getmtime", return_value=200.0):
        await _IndexerCircuitBreaker.check()

    assert _IndexerCircuitBreaker._open_until is None


@pytest.mark.asyncio
@pytest.mark.parametrize("indexer_extra, hosts", [
    ({"ssl": {"certificate": "etc/certs/indexer-connector.pem"}}, ("https://localhost:9200",)),
    ({}, ("https://node1:9200", "http://node2:9200")),
    ({}, ()),
], ids=["certificate-without-key", "mixed-schemes", "no-hosts"])
async def test_get_indexer_client_reports_unusable_configuration_as_configuration_error(indexer_extra, hosts):
    """Failures that retrying cannot fix are IndexerConfigurationError, so clusterd reports them once instead
    of backing off as for an outage. It stays an IndexerUnavailableError for every existing handler."""
    from wazuh.core.exception import IndexerConfigurationError

    with pytest.raises(IndexerConfigurationError) as error:
        await _run_get_indexer_client(indexer_extra, hosts=hosts)

    assert isinstance(error.value, IndexerUnavailableError)


@pytest.mark.asyncio
async def test_get_indexer_client_missing_keystore_entry_is_a_configuration_error():
    from wazuh.core.exception import IndexerConfigurationError

    keystore_client = MagicMock()
    keystore_client.__enter__.return_value.get.side_effect = KeyError("indexer/username")
    with patch("wazuh.core.indexer.indexer._get_cached_indexer_config", new_callable=AsyncMock,
               return_value={"indexer": {"hosts": ["https://localhost:9200"]}}), \
            patch("wazuh.core.indexer.indexer.KeystoreClient", return_value=keystore_client), \
            patch("wazuh.core.indexer.indexer._IndexerCircuitBreaker.check", new_callable=AsyncMock):
        with pytest.raises(IndexerConfigurationError, match="Missing credential entry"):
            async with get_indexer_client():
                pass


@pytest.mark.asyncio
async def test_get_indexer_client_unreachable_keystore_is_not_a_configuration_error():
    """The keystore daemon being down is transient: it keeps the outage backoff."""
    from wazuh.core.exception import IndexerConfigurationError

    keystore_client = MagicMock()
    keystore_client.__enter__.return_value.get.side_effect = ConnectionRefusedError("keystore.sock")
    with patch("wazuh.core.indexer.indexer._get_cached_indexer_config", new_callable=AsyncMock,
               return_value={"indexer": {"hosts": ["https://localhost:9200"]}}), \
            patch("wazuh.core.indexer.indexer.KeystoreClient", return_value=keystore_client), \
            patch("wazuh.core.indexer.indexer._IndexerCircuitBreaker.check", new_callable=AsyncMock):
        with pytest.raises(IndexerUnavailableError, match="Keystore operation failed") as error:
            async with get_indexer_client():
                pass

    assert not isinstance(error.value, IndexerConfigurationError)
