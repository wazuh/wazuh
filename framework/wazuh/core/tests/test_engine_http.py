# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import MagicMock, patch

import pytest

_httpx_mock = MagicMock()


class _TimeoutException(Exception):
    pass


class _ConnectError(Exception):
    pass


class _RequestError(Exception):
    pass


_httpx_mock.TimeoutException = _TimeoutException
_httpx_mock.ConnectError = _ConnectError
_httpx_mock.RequestError = _RequestError
_httpx_mock.HTTPTransport = MagicMock()
_httpx_mock.Client = MagicMock()

with patch.dict(sys.modules, {'httpx': _httpx_mock}), \
     patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/wazuh-manager/queue/sockets/analysis'):
    from wazuh.core.engine_http import EngineHTTPClient

from wazuh.core.exception import WazuhError, WazuhInternalError


METRICS_DUMP_RESPONSE = {
    "status": 0,
    "name": "engine",
    "uptime": 12345,
    "global": [
        {"name": "router.queue.size", "type": 0, "enabled": True, "value": 1000},
        {"name": "router.eps.1m", "type": 1, "enabled": True, "value": 250.5},
    ],
    "spaces": [],
}


def _make_client() -> EngineHTTPClient:
    client = EngineHTTPClient()
    client._client = MagicMock()
    return client


def test_get_metrics_dump_ok():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = METRICS_DUMP_RESPONSE
    client._client.post.return_value = mock_response

    result = client.get_metrics_dump()

    client._client.post.assert_called_once_with(
        url='http://localhost/metrics/dump',
        content='{}',
        headers={'Content-Type': 'text/plain'},
    )
    assert result == METRICS_DUMP_RESPONSE


def test_get_metrics_dump_http_error():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = True
    mock_response.text = 'internal error'
    client._client.post.return_value = mock_response

    with pytest.raises(WazuhError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2019


def test_get_metrics_dump_timeout():
    client = _make_client()
    client._client.post.side_effect = _TimeoutException("timed out")

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2020


def test_get_metrics_dump_connect_error():
    client = _make_client()
    client._client.post.side_effect = _ConnectError("refused")

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2021


def test_get_metrics_dump_request_error():
    client = _make_client()
    client._client.post.side_effect = _RequestError("network error")

    with pytest.raises(WazuhError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2013
