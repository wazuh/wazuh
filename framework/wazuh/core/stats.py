# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
import logging
from typing import NamedTuple, Optional, Union

from wazuh.core import common, utils
from wazuh.core import wazuh_socket
from wazuh.core.engine_http import RemotedHTTPClient
from wazuh.core.exception import WazuhException, WazuhInternalError

logger = logging.getLogger('wazuh')


class _Histogram(NamedTuple):
    """Marks a source metric whose `summary` distribution is projected instead of its `value`."""

    name: str


# ---------------------------------------------------------------------------------------------
# Projection of remoted's HTTPS metrics registry onto the daemons-stats response.
#
# `wazuh-manager-remoted`'s legacy `getstats` counters only ever move on the legacy TCP/UDP
# channel, which is disabled by default in 5.x. Everything the HTTPS agent server does is
# metered in the C++ module's `wazuh_metrics` registry instead, served as a flat, self-describing
# array on `GET /metrics` over the module's local admin socket. The tables below are the single
# place those metric names are written; they project that array onto a typed, nested object
# published as `metrics.http_server`.
#
# The whole `remoted.*` catalog is reported except `remoted.admin.server.*`, which describes the
# very socket used to fetch the dump. A metric missing from the dump omits its field rather than
# reporting a zero, so a rename on the C++ side surfaces as an absent field instead of a
# convincing but false counter.
# ---------------------------------------------------------------------------------------------

# Endpoints whose `remoted.http.<endpoint>.responses.*` family the module registers.
_HTTP_ENDPOINTS = ('stateless', 'stateful', 'stats', 'config', 'enroll')

# The closed status set of that family; some cells are structurally zero for a given endpoint
# but are kept so every endpoint reports the same vocabulary.
_HTTP_STATUS_CELLS = ('2xx', '400', '403', '409', '413', '500', '503', 'other')

# Endpoints that additionally resolve a `remoted.http.<endpoint>.latency` histogram.
_HTTP_LATENCY_ENDPOINTS = ('stateless', 'stateful', 'enroll')

# The distribution keys a histogram entry carries in its `summary` object.
_HISTOGRAM_KEYS = ('count', 'sum', 'min', 'max', 'p50', 'p90', 'p99')

_AUTH_REJECT_REASONS = (
    'unknown_agent',
    'invalid_signature',
    'bad_token',
    'identity_mismatch',
    'clock_skew',
    'unusable_key',
    'address_not_allowed',
    'enrollment_key_unavailable',
    'payload_mismatch',
    'body_too_large',
    'bad_encoding',
    'malformed',
)

# {output group: {output field: source metric name | nested spec | _Histogram}}
_REMOTED_METRIC_GROUPS = {
    'auth_rejections': {reason: f'remoted.auth.reject.{reason}' for reason in _AUTH_REJECT_REASONS},
    'enrollment': {
        'accepted': 'remoted.enroll.accepted',
        'rejected_auth': 'remoted.enroll.rejected_auth',
        'rejected_validation': 'remoted.enroll.rejected_validation',
        'disabled': 'remoted.enroll.disabled',
        'authd_error': 'remoted.enroll.authd_error',
        'authd_unavailable': 'remoted.enroll.authd_unavailable',
        'authd_queue': {
            'depth': 'remoted.enroll.authd.queue.depth',
            'capacity': 'remoted.enroll.authd.queue.capacity',
            'rejected_total': 'remoted.enroll.authd.queue.rejected.total',
        },
    },
    'control': {
        'startup': 'remoted.control.startup',
        'notify': 'remoted.control.notify',
        'shutdown': 'remoted.control.shutdown',
        'rejected': 'remoted.control.rejected',
        'wdb_error': 'remoted.control.wdb_error',
        'task_fetch': 'remoted.control.task_fetch',
        'task_fetch_error': 'remoted.control.task_fetch_error',
        'registry_agents': 'remoted.control.registry.agents',
        'wdb_latency': _Histogram('remoted.control.wdb.latency'),
    },
    'keystore': {
        'agents': 'remoted.auth.keystore.agents',
        'entries_skipped': 'remoted.auth.keystore.entries_skipped',
        'reloads_total': 'remoted.auth.keystore.reloads.total',
        'reload_failures_total': 'remoted.auth.keystore.reload_failures.total',
    },
    'downstream': {
        'downstream_5xx': 'remoted.forwarder.downstream_5xx',
        'route_mismatch': 'remoted.forwarder.route_mismatch',
        'errors': {
            'connect': 'remoted.forwarder.error.connect',
            'connect_timeout': 'remoted.forwarder.error.connect_timeout',
            'write_timeout': 'remoted.forwarder.error.write_timeout',
            'response_timeout': 'remoted.forwarder.error.response_timeout',
            'transport': 'remoted.forwarder.error.transport',
            'protocol': 'remoted.forwarder.error.protocol',
            'response_too_large': 'remoted.forwarder.error.response_too_large',
        },
        'deferred': {
            'capacity': 'remoted.forwarder.deferred.capacity',
            'inflight': 'remoted.forwarder.deferred.inflight',
            'rejected_total': 'remoted.forwarder.deferred.rejected.total',
        },
    },
    'backpressure': {
        'available_bytes': 'remoted.server.budget.available.bytes',
        'inflight_bytes': 'remoted.server.budget.inflight.bytes',
        'inflight_requests': 'remoted.server.budget.inflight.requests',
        'rejected_total': 'remoted.server.budget.rejected.total',
    },
    'downloads': {
        'started': 'remoted.download.started',
        'rejected': 'remoted.download.rejected',
        'not_found': 'remoted.download.not_found',
        'open_error': 'remoted.download.open_error',
        'bytes_total': 'remoted.download.bytes.total',
    },
    'vd_scan': {
        'requests_total': 'remoted.scanvd.requests.total',
        'accepted': 'remoted.scanvd.accepted',
        'version_mismatch': 'remoted.scanvd.version_mismatch',
        'queue_full': 'remoted.scanvd.queue_full',
        'invalid_agent': 'remoted.scanvd.invalid_agent',
        'vd_error': 'remoted.scanvd.vd_error',
        'indexer_unavailable': 'remoted.scanvd.indexer_unavailable',
    },
}


def _index_dump(dump: dict) -> dict:
    """Index a metrics dump envelope by metric name.

    Parameters
    ----------
    dump : dict
        Dump envelope as served by remoted's admin `GET /metrics`.

    Returns
    -------
    dict
        Mapping of metric name to its entry. Malformed or unnamed entries are skipped.
    """
    if not isinstance(dump, dict):
        return {}

    metrics = dump.get('metrics')
    if not isinstance(metrics, list):
        return {}

    return {entry['name']: entry for entry in metrics if isinstance(entry, dict) and isinstance(entry.get('name'), str)}


def _value(index: dict, name: str) -> Optional[Union[int, float]]:
    """Read a counter, gauge or pull metric's current value, or None when it is not reported.

    A whole-number float is normalized to an int: the dump serializes every metric that is not a
    counter, gauge or histogram as a JSON double, so a `pull` metric counting agents arrives as
    `12.0`. They are all integer quantities — counts, bytes, queue depths — and the API reports
    them as integers. A genuinely fractional value is left alone; none exists in remoted's
    catalog today, and adding one means editing the tables above anyway.
    """
    entry = index.get(name)
    if not isinstance(entry, dict):
        return None

    value = entry.get('value')
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    return int(value) if isinstance(value, float) and value.is_integer() else value


def _summary(index: dict, name: str) -> Optional[dict]:
    """Read a histogram metric's distribution, or None when it is not reported.

    Returns
    -------
    dict or None
        The `summary` object projected onto `_HISTOGRAM_KEYS`. None when the metric is absent
        or carries no distribution (i.e. it is not a histogram).
    """
    entry = index.get(name)
    if not isinstance(entry, dict):
        return None

    summary = entry.get('summary')
    if not isinstance(summary, dict):
        return None

    projected = {key: summary[key] for key in _HISTOGRAM_KEYS if key in summary}
    return projected or None


def _project(index: dict, spec: Union[str, dict, _Histogram]) -> Optional[Union[int, float, dict]]:
    """Resolve a group spec against an indexed dump, dropping whatever is not reported.

    Parameters
    ----------
    index : dict
        Indexed dump, as returned by `_index_dump`.
    spec : str or dict or _Histogram
        A source metric name, a nested spec, or a histogram marker.

    Returns
    -------
    int or float or dict or None
        None when nothing under `spec` is reported, so the caller can omit the field entirely
        instead of publishing a zero that no component ever produced.
    """
    if isinstance(spec, _Histogram):
        return _summary(index, spec.name)

    if isinstance(spec, str):
        return _value(index, spec)

    projected = {}
    for field, sub_spec in spec.items():
        value = _project(index, sub_spec)
        if value is not None:
            projected[field] = value

    return projected or None


def _project_responses(index: dict) -> dict:
    """Project the `remoted.http.<endpoint>.responses.*` families, one object per endpoint.

    Each endpoint gets the reported status cells plus a `total` rollup of them. An endpoint
    whose family is entirely absent from the dump is omitted.
    """
    responses = {}
    for endpoint in _HTTP_ENDPOINTS:
        cells = {}
        for cell in _HTTP_STATUS_CELLS:
            value = _value(index, f'remoted.http.{endpoint}.responses.{cell}')
            if value is not None:
                cells[cell] = value

        if cells:
            responses[endpoint] = {'total': sum(cells.values()), **cells}

    return responses


def _project_latency(index: dict) -> dict:
    """Project the `remoted.http.<endpoint>.latency` histograms, in microseconds."""
    latency = {}
    for endpoint in _HTTP_LATENCY_ENDPOINTS:
        summary = _summary(index, f'remoted.http.{endpoint}.latency')
        if summary is not None:
            latency[endpoint] = summary

    return latency


def build_remoted_http_metrics(dump: dict) -> dict:
    """Project remoted's metrics dump onto the `metrics.http_server` object of the stats response.

    Parameters
    ----------
    dump : dict
        Dump envelope as served by remoted's admin `GET /metrics`.

    Returns
    -------
    dict
        The typed, nested projection. Fields, and whole groups, backed by a metric the dump does
        not report are omitted rather than reported as zero. `remoted.admin.server.*` metrics are
        never included: they describe the admin socket the dump itself was read from.
    """
    index = _index_dump(dump)
    http_metrics = {}

    timestamp = dump.get('timestamp') if isinstance(dump, dict) else None
    if isinstance(timestamp, str):
        http_metrics['timestamp'] = timestamp

    for group, projection in (('responses', _project_responses(index)), ('latency', _project_latency(index))):
        if projection:
            http_metrics[group] = projection

    for group, spec in _REMOTED_METRIC_GROUPS.items():
        projection = _project(index, spec)
        if projection is None:
            continue
        if group == 'auth_rejections':
            # Rolled up here rather than in the table: the reasons are a partition of every
            # gateway rejection, and only the reported ones may be counted.
            total = sum(value for value in projection.values() if isinstance(value, (int, float)))
            projection = {'total': total, **projection}
        http_metrics[group] = projection

    return http_metrics


def get_daemons_stats_socket(socket: str) -> dict:
    """Send message to Wazuh socket to get statistical information.

    Parameters
    ----------
    socket : str
        Full path of the socket to communicate with.

    Raises
    ------
    WazuhInternalError (1121)
        If there was an error when trying to connect to the socket.

    Returns
    -------
    dict
        Dictionary with daemon's statistical information.
    """
    # Create message
    full_message = wazuh_socket.create_wazuh_socket_message(
        origin={'module': common.origin_module.get()},
        command='getstats'
    )

    # Connect to socket
    try:
        s = wazuh_socket.WazuhSocketJSON(socket)
    except Exception:
        raise WazuhInternalError(1121, extra_message=socket)

    # Send message and receive socket response
    try:
        s.send(full_message)
        response = s.receive()
    finally:
        s.close()

    # Timestamps transformations
    with contextlib.suppress(KeyError):
        response['timestamp'] = utils.get_date_from_timestamp(response['timestamp'])
        response['uptime'] = utils.get_date_from_timestamp(response['uptime'])

    return response


def get_remoted_daemon_stats() -> dict:
    """Get statistical information from `wazuh-manager-remoted`, both channels combined.

    The legacy counters are read with `getstats` over remoted's control socket; the HTTPS agent
    server's statistics are read from the module's local admin socket and folded in under
    `metrics.http_server`.

    Raises
    ------
    WazuhInternalError (1121)
        If there was an error when trying to connect to remoted's control socket.

    Returns
    -------
    dict
        Dictionary with remoted's statistical information. `metrics.http_server` is absent when
        the module's admin socket could not be read: it is an optional, best-effort surface (a
        failed bind is a warning inside remoted, never fatal), so it must not fail the request.
    """
    stats = get_daemons_stats_socket(common.REMOTED_SOCKET)

    try:
        client = RemotedHTTPClient()
        try:
            dump = client.get_metrics_dump()
        finally:
            client.close()
    except WazuhException as exc:
        logger.warning(f'Could not read the HTTPS agent server statistics from remoted: {exc}')
        return stats

    stats.setdefault('metrics', {})['http_server'] = build_remoted_http_metrics(dump)

    return stats
