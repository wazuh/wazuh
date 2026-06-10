# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh.core.indexer.indexer import get_indexer_client, resolve_wazuh_path


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
        {"value": "wazuh-server"},
        {"value": "wazuh-server"},
    ]

    wazuh_config = {
        "indexer": {
            "hosts": ["https://localhost:9200"],
            "ssl": {
                "certificate_authorities": [{"ca": ["etc/certs/root-ca.pem"]}],
                "certificate": ["etc/certs/manager.pem"],
                "key": ["etc/certs/manager-key.pem"],
            },
        }
    }

    with patch("wazuh.core.indexer.indexer.common.WAZUH_PATH", "/var/wazuh-manager"), \
            patch(
                "wazuh.core.indexer.indexer.get_ossec_conf",
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
            ) as create_indexer:
        async with get_indexer_client():
            pass

    create_indexer.assert_awaited_once_with(
        hosts=["localhost"],
        ports=[9200],
        user="wazuh-server",
        password="wazuh-server",
        use_ssl=True,
        verify_certs=True,
        client_cert_path="/var/wazuh-manager/etc/certs/manager.pem",
        client_key_path="/var/wazuh-manager/etc/certs/manager-key.pem",
        ca_certs_path="/var/wazuh-manager/etc/certs/root-ca.pem",
    )
    client.close.assert_awaited_once()
