# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.core import stats
        from wazuh.core.exception import WazuhInternalError
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.close')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.send')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.__init__', return_value=None)
def test_get_daemons_stats_socket(mock__init__, mock_send, mock_close):
    """Verify get_daemons_stats_socket(socket : str) function works as expected"""
    socket = '/test_path/socket'
    expected_msg = {'version': 1, 'origin': {'module': 'framework'}, 'command': 'getstats'}
    expected_socket_response = {'timestamp': 1658400850, 'uptime': 1658400850, 'stats': 'value'}
    expected_result = {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
                       'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
                       'stats': 'value'}

    with patch('wazuh.core.wazuh_socket.WazuhSocketJSON.receive',
               return_value=expected_socket_response) as mock_receive:
        result = stats.get_daemons_stats_socket(socket)

        mock__init__.assert_called_once_with(socket)
        mock_send.assert_called_once_with(expected_msg)
        mock_receive.assert_called_once()
        mock_close.assert_called_once()
        assert result == expected_result


def test_get_daemons_stats_socket_ko():
    """Test get_daemons_stats_socket(socket : str) function exception works"""
    socket = '/test_path/socket'
    with pytest.raises(WazuhInternalError, match=f".* 1121 .*: {socket}"):
        stats.get_daemons_stats_socket(socket)


# ---------------------------------------------------------------------------------------------
# metrics.http_server: the projection of remoted's HTTPS metrics registry
# ---------------------------------------------------------------------------------------------

# A capture of remoted's admin `GET /metrics`, covering the whole registered catalog. Values are
# unique and grouped by decade so a mis-mapped metric name lands a recognizably wrong number in
# the expected projection below instead of quietly matching.
def _load_dump() -> dict:
    with open(os.path.join(DATA_PATH, 'remoted_metrics_dump.json')) as dump_file:
        return json.load(dump_file)


REMOTED_METRICS_DUMP = _load_dump()

EXPECTED_HTTP_SERVER_METRICS = {
    'timestamp': '2026-09-04T10:48:32Z',
    'responses': {
        'stateless': {'total': 8836, '2xx': 1101, '400': 1102, '403': 1103, '409': 1104, '413': 1105,
                      '500': 1106, '503': 1107, 'other': 1108},
        'stateful': {'total': 9636, '2xx': 1201, '400': 1202, '403': 1203, '409': 1204, '413': 1205,
                     '500': 1206, '503': 1207, 'other': 1208},
        'stats': {'total': 10436, '2xx': 1301, '400': 1302, '403': 1303, '409': 1304, '413': 1305,
                  '500': 1306, '503': 1307, 'other': 1308},
        'config': {'total': 11236, '2xx': 1401, '400': 1402, '403': 1403, '409': 1404, '413': 1405,
                   '500': 1406, '503': 1407, 'other': 1408},
        'enroll': {'total': 12036, '2xx': 1501, '400': 1502, '403': 1503, '409': 1504, '413': 1505,
                   '500': 1506, '503': 1507, 'other': 1508},
    },
    'latency': {
        'stateless': {'count': 8100, 'sum': 8101, 'min': 8102, 'max': 8103, 'p50': 8104, 'p90': 8105,
                      'p99': 8106},
        'stateful': {'count': 8200, 'sum': 8201, 'min': 8202, 'max': 8203, 'p50': 8204, 'p90': 8205,
                     'p99': 8206},
        'enroll': {'count': 8300, 'sum': 8301, 'min': 8302, 'max': 8303, 'p50': 8304, 'p90': 8305,
                   'p99': 8306},
    },
    'auth_rejections': {'total': 12078, 'unknown_agent': 1001, 'invalid_signature': 1002, 'bad_token': 1003,
                        'identity_mismatch': 1004, 'clock_skew': 1005, 'unusable_key': 1006,
                        'address_not_allowed': 1007, 'enrollment_key_unavailable': 1008,
                        'payload_mismatch': 1009, 'body_too_large': 1010, 'bad_encoding': 1011,
                        'malformed': 1012},
    'enrollment': {'accepted': 2001, 'rejected_auth': 2002, 'rejected_validation': 2003, 'disabled': 2004,
                   'authd_error': 2005, 'authd_unavailable': 2006,
                   'authd_queue': {'depth': 2007, 'capacity': 2008, 'rejected_total': 2009}},
    'control': {'startup': 3001, 'notify': 3002, 'shutdown': 3003, 'rejected': 3004, 'wdb_error': 3005,
                'task_fetch': 3006, 'task_fetch_error': 3007, 'registry_agents': 3008,
                'wdb_latency': {'count': 3100, 'sum': 3101, 'min': 3102, 'max': 3103, 'p50': 3104,
                                'p90': 3105, 'p99': 3106}},
    'keystore': {'agents': 4001, 'entries_skipped': 4002, 'reloads_total': 4004, 'reload_failures_total': 4003},
    'downstream': {'downstream_5xx': 5001, 'route_mismatch': 5002,
                   'errors': {'connect': 5003, 'connect_timeout': 5004, 'write_timeout': 5005,
                              'response_timeout': 5006, 'transport': 5007, 'protocol': 5008,
                              'response_too_large': 5009},
                   'deferred': {'capacity': 5010, 'inflight': 5011, 'rejected_total': 5012}},
    'backpressure': {'available_bytes': 6001, 'inflight_bytes': 6002, 'inflight_requests': 6003,
                     'rejected_total': 6004},
    'downloads': {'started': 7001, 'rejected': 7002, 'not_found': 7003, 'open_error': 7004,
                  'bytes_total': 7005},
    'vd_scan': {'requests_total': 8001, 'accepted': 8002, 'version_mismatch': 8003, 'queue_full': 8004,
                'invalid_agent': 8005, 'vd_error': 8006, 'indexer_unavailable': 8007},
}


def _dump_without(*names: str) -> dict:
    """Return a copy of the reference dump with the named metrics removed."""
    dump = copy.deepcopy(REMOTED_METRICS_DUMP)
    dump['metrics'] = [entry for entry in dump['metrics'] if entry['name'] not in names]
    return dump


def test_build_remoted_http_metrics():
    """The whole registered catalog is projected onto the documented metrics.http_server shape."""
    assert stats.build_remoted_http_metrics(REMOTED_METRICS_DUMP) == EXPECTED_HTTP_SERVER_METRICS


def test_build_remoted_http_metrics_never_reports_the_admin_socket():
    """`remoted.admin.server.*` describes the socket the dump was read from: it must never leak."""
    admin_values = {entry['value'] for entry in REMOTED_METRICS_DUMP['metrics']
                    if entry['name'].startswith('remoted.admin.server.')}

    result = json.dumps(stats.build_remoted_http_metrics(REMOTED_METRICS_DUMP))

    assert admin_values, 'the reference dump must carry admin metrics for this test to mean anything'
    assert 'admin' not in result
    assert not any(str(value) in result for value in admin_values)


def test_build_remoted_http_metrics_omits_missing_fields_instead_of_reporting_zero():
    """A metric absent from the dump omits its field, so a rename cannot read as a real zero."""
    dump = _dump_without('remoted.auth.reject.bad_token', 'remoted.download.bytes.total',
                         'remoted.enroll.authd.queue.depth', 'remoted.http.stateless.responses.503')

    result = stats.build_remoted_http_metrics(dump)

    assert 'bad_token' not in result['auth_rejections']
    assert 'bytes_total' not in result['downloads']
    assert 'depth' not in result['enrollment']['authd_queue']
    assert '503' not in result['responses']['stateless']
    # Siblings are untouched, and the rollups only ever count what was actually reported.
    assert result['auth_rejections']['invalid_signature'] == 1002
    assert result['auth_rejections']['total'] == EXPECTED_HTTP_SERVER_METRICS['auth_rejections']['total'] - 1003
    assert result['downloads']['started'] == 7001
    assert result['enrollment']['authd_queue'] == {'capacity': 2008, 'rejected_total': 2009}
    assert result['responses']['stateless']['total'] == 8836 - 1107


def test_build_remoted_http_metrics_omits_groups_and_endpoints_that_report_nothing():
    """A group, sub-object or endpoint whose every metric is absent is dropped entirely."""
    dump = _dump_without(
        *[entry['name'] for entry in REMOTED_METRICS_DUMP['metrics']
          if entry['name'].startswith(('remoted.scanvd.', 'remoted.enroll.authd.queue.',
                                       'remoted.http.config.responses.'))])

    result = stats.build_remoted_http_metrics(dump)

    assert 'vd_scan' not in result
    assert 'authd_queue' not in result['enrollment']
    assert 'config' not in result['responses']
    assert result['enrollment']['accepted'] == 2001, 'the rest of the group must survive'
    assert 'stateless' in result['responses']


def test_build_remoted_http_metrics_reports_pull_metrics_as_integers():
    """Pull metrics arrive as JSON doubles and must be reported as ints, or the API 500s.

    `jsonDump.cpp` serializes anything that is not a counter, gauge or histogram with
    `writer.Double()`, so every `pull` metric — keystore, backpressure, deferred, authd queue,
    control registry — comes back as `12.0`. The spec declares those fields as integers, and the
    API validates its own responses against it, so a float there fails validation and the whole
    endpoint answers 500.
    """
    pulls = {entry['name'] for entry in REMOTED_METRICS_DUMP['metrics'] if entry['type'] == 'pull'}
    assert pulls, 'the reference dump must carry pull metrics for this test to mean anything'
    assert all(isinstance(entry['value'], float)
               for entry in REMOTED_METRICS_DUMP['metrics'] if entry['name'] in pulls), \
        'the reference dump must emit them as doubles, exactly as the daemon does'

    result = stats.build_remoted_http_metrics(REMOTED_METRICS_DUMP)

    def numbers(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from numbers(value)
        elif isinstance(node, (int, float)):
            yield node

    floats = [value for value in numbers(result) if isinstance(value, float)]
    assert not floats, f'every reported value must be an int, found floats: {floats}'
    # Spot-check the pull-backed groups specifically.
    assert result['keystore'] == {'agents': 4001, 'entries_skipped': 4002, 'reloads_total': 4004,
                                  'reload_failures_total': 4003}
    assert result['backpressure']['available_bytes'] == 6001
    assert result['control']['registry_agents'] == 3008


def test_build_remoted_http_metrics_omits_latency_without_a_distribution():
    """A histogram entry with no `summary` is omitted rather than reported as a bare count."""
    dump = copy.deepcopy(REMOTED_METRICS_DUMP)
    for entry in dump['metrics']:
        if entry['name'] in ('remoted.http.stateful.latency', 'remoted.control.wdb.latency'):
            del entry['summary']

    result = stats.build_remoted_http_metrics(dump)

    assert 'stateful' not in result['latency']
    assert 'stateless' in result['latency']
    assert 'wdb_latency' not in result['control']
    assert result['control']['notify'] == 3002


@pytest.mark.parametrize('dump, expected', [
    ({}, {}),
    ({'metrics': []}, {}),
    ({'metrics': 'not-a-list'}, {}),
    ({'timestamp': 1658400850, 'metrics': []}, {}),
    ({'timestamp': '2026-09-04T10:48:32Z', 'metrics': [1, None, {'no_name': 0}, {'name': 0, 'value': 1}]},
     {'timestamp': '2026-09-04T10:48:32Z'}),
    ({'timestamp': '2026-09-04T10:48:32Z',
      'metrics': [{'name': 'remoted.control.notify', 'value': None},
                  {'name': 'remoted.control.startup', 'value': True},
                  {'name': 'remoted.control.shutdown', 'value': 'many'},
                  {'name': 'remoted.control.rejected', 'value': 7}]},
     {'timestamp': '2026-09-04T10:48:32Z', 'control': {'rejected': 7}}),
], ids=['empty', 'no-metrics', 'metrics-not-a-list', 'non-string-timestamp', 'junk-entries',
        'non-numeric-values'])
def test_build_remoted_http_metrics_tolerates_malformed_dumps(dump, expected):
    """A dump that does not look like the contract yields whatever is usable, never an exception."""
    assert stats.build_remoted_http_metrics(dump) == expected


LEGACY_REMOTED_STATS = {
    'uptime': datetime(2022, 7, 21, 10, 9, 20, tzinfo=timezone.utc),
    'timestamp': datetime(2022, 7, 21, 10, 48, 32, tzinfo=timezone.utc),
    'name': 'wazuh-manager-remoted',
    'metrics': {'bytes': {'received': 0, 'sent': 0}, 'tcp_sessions': 0},
}


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote.sock')
@patch('wazuh.core.stats.RemotedHTTPClient')
@patch('wazuh.core.stats.get_daemons_stats_socket', return_value=copy.deepcopy(LEGACY_REMOTED_STATS))
def test_get_remoted_daemon_stats(mock_get_socket, mock_client_cls):
    """Both remoted channels are read and combined, the legacy keys untouched."""
    mock_client = MagicMock()
    mock_client.get_metrics_dump.return_value = REMOTED_METRICS_DUMP
    mock_client_cls.return_value = mock_client

    result = stats.get_remoted_daemon_stats()

    mock_get_socket.assert_called_once_with('/var/wazuh-manager/queue/sockets/remote.sock')
    mock_client.get_metrics_dump.assert_called_once()
    mock_client.close.assert_called_once()
    assert result['metrics']['http_server'] == EXPECTED_HTTP_SERVER_METRICS
    assert {key: result[key] for key in ('uptime', 'timestamp', 'name')} == \
           {key: LEGACY_REMOTED_STATS[key] for key in ('uptime', 'timestamp', 'name')}
    assert result['metrics']['bytes'] == {'received': 0, 'sent': 0}
    assert result['metrics']['tcp_sessions'] == 0


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote.sock')
@patch('wazuh.core.stats.logger')
@patch('wazuh.core.stats.RemotedHTTPClient')
@patch('wazuh.core.stats.get_daemons_stats_socket', return_value=copy.deepcopy(LEGACY_REMOTED_STATS))
def test_get_remoted_daemon_stats_admin_socket_unavailable(mock_get_socket, mock_client_cls, mock_logger):
    """The admin socket is optional: an unreachable one drops the key, it never fails the request."""
    mock_client = MagicMock()
    mock_client.get_metrics_dump.side_effect = WazuhInternalError(2031)
    mock_client_cls.return_value = mock_client

    result = stats.get_remoted_daemon_stats()

    assert 'http_server' not in result['metrics']
    assert result['metrics']['bytes'] == {'received': 0, 'sent': 0}
    mock_client.close.assert_called_once(), 'the client must be closed even when the request failed'
    # Asserted on the module's logger rather than caplog: `wlogging` sets propagate=False on the
    # `wazuh` logger, so once anything in the session initializes it, caplog captures nothing.
    mock_logger.warning.assert_called_once()
    assert 'Could not read the HTTPS agent server statistics' in mock_logger.warning.call_args[0][0]


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote.sock')
@patch('wazuh.core.stats.RemotedHTTPClient')
@patch('wazuh.core.stats.get_daemons_stats_socket', side_effect=WazuhInternalError(1121))
def test_get_remoted_daemon_stats_ko(mock_get_socket, mock_client_cls):
    """A failure on the control socket still fails the whole item: there is nothing to report."""
    with pytest.raises(WazuhInternalError, match='.* 1121 .*'):
        stats.get_remoted_daemon_stats()

    mock_client_cls.assert_not_called()
