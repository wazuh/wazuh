/*
 * Wazuh remoted module - public transport backpressure metrics
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_TRANSPORT_METRICS_HPP
#define _REMOTED_HTTP_TRANSPORT_METRICS_HPP

/**
 * @file transportMetrics.hpp
 * @brief Names of the public listener's backpressure pulls (`remoted.server.budget.*`,
 *        `remoted.server.connections.{open,max}`) on the shared `wazuh_metrics` registry.
 *
 * Registered by the facade (registerPublicTransportDiagnostics()) over IHttpServer::diagnostics(),
 * next to the handshake-guard pulls of handshakeMetrics.hpp and the certificate pulls of
 * endpoints/cacertsMetrics.hpp, which read the same weak target.
 */

namespace remoted::http::metrics
{
    /// Gauge: bytes the in-flight payload budget can still admit ('remoted.max_inflight_bytes').
    constexpr auto METRIC_BUDGET_AVAILABLE_BYTES {"remoted.server.budget.available.bytes"};
    /// Gauge: bytes reserved by admitted requests (payloads plus zstd decode scratch).
    constexpr auto METRIC_BUDGET_INFLIGHT_BYTES {"remoted.server.budget.inflight.bytes"};
    /// Gauge: admitted requests currently holding a reservation.
    constexpr auto METRIC_BUDGET_INFLIGHT_REQUESTS {"remoted.server.budget.inflight.requests"};
    /// Counter: requests the byte budget refused (503, before any route ran).
    constexpr auto METRIC_BUDGET_REJECTED_TOTAL {"remoted.server.budget.rejected.total"};
    /// Gauge: connections open on the listener.
    constexpr auto METRIC_CONNECTIONS_OPEN {"remoted.server.connections.open"};
    /// Gauge: connections the listener accepts at once ('remoted.max_parallel_connections').
    constexpr auto METRIC_CONNECTIONS_MAX {"remoted.server.connections.max"};
} // namespace remoted::http::metrics

#endif // _REMOTED_HTTP_TRANSPORT_METRICS_HPP
