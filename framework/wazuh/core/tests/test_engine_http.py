# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch

import pytest
import httpx

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
    with patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/wazuh-manager/queue/sockets/analysis'):
        with patch('httpx.HTTPTransport'), patch('httpx.Client'):
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
        headers={'Content-Type': 'application/json'},
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


def test_get_metrics_dump_invalid_json():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.side_effect = ValueError("not valid json")
    client._client.post.return_value = mock_response

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2022


def test_get_metrics_dump_timeout():
    client = _make_client()
    client._client.post.side_effect = httpx.TimeoutException("timed out", request=MagicMock())

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2020


def test_get_metrics_dump_connect_error():
    client = _make_client()
    client._client.post.side_effect = httpx.ConnectError("refused", request=MagicMock())

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2021


def test_get_metrics_dump_request_error():
    client = _make_client()
    client._client.post.side_effect = httpx.RequestError("network error", request=MagicMock())

    with pytest.raises(WazuhError) as exc_info:
        client.get_metrics_dump()
    assert exc_info.value.code == 2013


STATUS_RESPONSE = {
    "status": "OK",
    "ready": True,
    "spaces": {
        "standard": {"available": True, "enabled": True, "status": "ready", "hash": "abc", "last_successful_update": 1},
    },
    "ioc": {
        "connection": {"available": True, "status": "ready", "hash": "def", "last_successful_update": 1},
    },
    "geo": {
        "city": {"available": True, "status": "ready", "hash": "ghi", "last_successful_update": 1},
    },
}


def test_get_status_ok():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = STATUS_RESPONSE
    client._client.get.return_value = mock_response

    result = client.get_status()

    client._client.get.assert_called_once_with(
        url='http://localhost/status',
        headers={'Content-Type': 'application/json'},
    )
    assert result == STATUS_RESPONSE


def test_get_status_http_error():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = True
    mock_response.text = 'internal error'
    client._client.get.return_value = mock_response

    with pytest.raises(WazuhError) as exc_info:
        client.get_status()
    assert exc_info.value.code == 2019


def test_get_status_invalid_json():
    client = _make_client()
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.side_effect = ValueError("not valid json")
    client._client.get.return_value = mock_response

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_status()
    assert exc_info.value.code == 2022


def test_get_status_timeout():
    client = _make_client()
    client._client.get.side_effect = httpx.TimeoutException("timed out", request=MagicMock())

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_status()
    assert exc_info.value.code == 2020


def test_get_status_connect_error():
    client = _make_client()
    client._client.get.side_effect = httpx.ConnectError("refused", request=MagicMock())

    with pytest.raises(WazuhInternalError) as exc_info:
        client.get_status()
    assert exc_info.value.code == 2021


def test_get_status_request_error():
    client = _make_client()
    client._client.get.side_effect = httpx.RequestError("network error", request=MagicMock())

    with pytest.raises(WazuhError) as exc_info:
        client.get_status()
    assert exc_info.value.code == 2013


def test_engine_http_client_init_error():
    """Test that the client raises WazuhInternalError(2018) if httpx instantiation fails."""
    with patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/wazuh-manager/queue/sockets/analysis'):
        # Simulate that httpx cannot open the Unix socket
        with patch('httpx.HTTPTransport', side_effect=OSError("no socket")):
            with pytest.raises(WazuhInternalError) as exc_info:
                EngineHTTPClient()
            assert exc_info.value.code == 2018
