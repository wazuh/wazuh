/*
 * Wazuh remoted module - TLS handshake guard metrics
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_HANDSHAKE_METRICS_HPP
#define _REMOTED_HTTP_HANDSHAKE_METRICS_HPP

/**
 * @file handshakeMetrics.hpp
 * @brief Names of the handshake-guard pulls on the shared `wazuh_metrics` registry (issue #6883).
 *
 * Registered by the facade over IHttpServer::diagnostics(), next to `remoted.server.connections.*`:
 * they read the transport's HandshakeLedger (http_server/handshakeLedger.hpp). Together they are what
 * shows the public listener's slots being held by peers that never complete a TLS handshake -- the
 * one way to fill max_parallel_connections that no request-level metric can see.
 */

namespace remoted::http::metrics
{
    /// Gauge: connections still in the TLS handshake (a subset of remoted.server.connections.open).
    constexpr auto METRIC_CONNECTIONS_HANDSHAKING {"remoted.server.connections.handshaking"};
    /// Counter: handshakes closed by the deadline (remoted.http_read_timeout).
    constexpr auto METRIC_HANDSHAKE_TIMEOUTS {"remoted.server.handshake.timeouts.total"};
    /// Counter: connections closed at once by the per-source cap (remoted.max_handshakes_per_source).
    constexpr auto METRIC_HANDSHAKE_REJECTED_PER_SOURCE {"remoted.server.handshake.rejected_per_source.total"};
} // namespace remoted::http::metrics

#endif // _REMOTED_HTTP_HANDSHAKE_METRICS_HPP
